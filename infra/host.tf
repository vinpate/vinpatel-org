locals {
  host_shape = "VM.Standard.E2.1.Micro"
}

# In regions with several availability domains, Always Free micro instances
# can be created in only one of them, and which one varies by tenancy.
data "oci_identity_availability_domains" "all" {
  compartment_id = var.tenancy_ocid
}

data "oci_core_shapes" "host" {
  for_each = toset(data.oci_identity_availability_domains.all.availability_domains[*].name)

  compartment_id      = var.compartment_ocid
  availability_domain = each.key

  filter {
    name   = "name"
    values = [local.host_shape]
  }
}

data "oci_core_images" "ubuntu" {
  compartment_id           = var.compartment_ocid
  operating_system         = "Canonical Ubuntu"
  operating_system_version = "24.04 Minimal"
  shape                    = local.host_shape
  sort_by                  = "TIMECREATED"
  sort_order               = "DESC"
}

resource "oci_core_vcn" "host" {
  compartment_id = var.compartment_ocid
  cidr_blocks    = ["10.0.0.0/16"]
  display_name   = "vinpatel-org"
}

resource "oci_core_internet_gateway" "host" {
  compartment_id = var.compartment_ocid
  vcn_id         = oci_core_vcn.host.id
  display_name   = "vinpatel-org"
}

resource "oci_core_route_table" "host" {
  compartment_id = var.compartment_ocid
  vcn_id         = oci_core_vcn.host.id
  display_name   = "vinpatel-org"

  route_rules {
    destination       = "0.0.0.0/0"
    destination_type  = "CIDR_BLOCK"
    network_entity_id = oci_core_internet_gateway.host.id
  }
}

# The site needs nothing inbound: cloudflared dials out. SSH is for the
# owner only. Fragmentation-needed ICMP is kept as in OCI's default list,
# since the VNIC's MTU is 9000 and path MTU discovery depends on it.
resource "oci_core_security_list" "host" {
  compartment_id = var.compartment_ocid
  vcn_id         = oci_core_vcn.host.id
  display_name   = "vinpatel-org"

  egress_security_rules {
    destination = "0.0.0.0/0"
    protocol    = "all"
  }

  ingress_security_rules {
    source   = var.ssh_cidr
    protocol = "6"

    tcp_options {
      min = 22
      max = 22
    }
  }

  ingress_security_rules {
    source   = "0.0.0.0/0"
    protocol = "1"

    icmp_options {
      type = 3
      code = 4
    }
  }
}

resource "oci_core_subnet" "host" {
  compartment_id    = var.compartment_ocid
  vcn_id            = oci_core_vcn.host.id
  cidr_block        = "10.0.0.0/24"
  route_table_id    = oci_core_route_table.host.id
  security_list_ids = [oci_core_security_list.host.id]
  display_name      = "vinpatel-org"
}

# Secrets never reach metadata or state: scripts/host-env.sh delivers them
# over SSH. A change to cloud-init.yaml or the SSH key replaces the
# instance, after which that script has to run again.
resource "oci_core_instance" "host" {
  compartment_id      = var.compartment_ocid
  availability_domain = [for ad, shapes in data.oci_core_shapes.host : ad if length(shapes.shapes) > 0][0]
  shape               = local.host_shape
  display_name        = "vinpatel-org"

  source_details {
    source_type             = "image"
    source_id               = data.oci_core_images.ubuntu.images[0].id
    boot_volume_size_in_gbs = 50
  }

  create_vnic_details {
    subnet_id        = oci_core_subnet.host.id
    assign_public_ip = true
  }

  metadata = {
    ssh_authorized_keys = var.ssh_public_key
    user_data           = filebase64("${path.module}/cloud-init.yaml")
  }

  # Canonical publishes new images often; unattended upgrades keep the
  # running one current, and a replacement picks up the newest anyway.
  lifecycle {
    ignore_changes = [source_details[0].source_id]
  }
}

resource "oci_core_instance_console_connection" "host" {
  instance_id = oci_core_instance.host.id
  public_key  = var.ssh_public_key
}

# Budgets live in the root compartment. This one covers the whole tenancy,
# so anything that leaves Always Free shows up, not only the host.
resource "oci_budget_budget" "tenancy" {
  compartment_id = var.tenancy_ocid
  amount         = 1
  reset_period   = "MONTHLY"
  target_type    = "COMPARTMENT"
  targets        = [var.tenancy_ocid]
  display_name   = "vinpatel-org"
}

resource "oci_budget_alert_rule" "tenancy" {
  budget_id      = oci_budget_budget.tenancy.id
  type           = "FORECAST"
  threshold      = 100
  threshold_type = "PERCENTAGE"
  recipients     = var.budget_email
  display_name   = "forecast-over-budget"
  message        = "The OCI tenancy behind vinpatel.org is forecast to cost money this month."
}
