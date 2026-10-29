// Package posture holds the domain's intended mail setup. The declaration,
// mail.json, is embedded here and read by Terraform, so the DNS records and
// the page's expectations come from one file.
package posture

import (
	_ "embed"
	"encoding/json/v2"
	"errors"
	"fmt"
	"slices"
	"strings"
)

//go:embed mail.json
var mailJSON []byte

// Declaration is the mail posture the domain intends to publish.
type Declaration struct {
	Domain string   `json:"domain"`
	MX     []string `json:"mx"`
	SPF    string   `json:"spf"` // the record text, published as is
	DKIM   DKIM     `json:"dkim"`
	DMARC  DMARC    `json:"dmarc"`
	MTASTS MTASTS   `json:"mta_sts"`
	TLSRPT TLSRPT   `json:"tls_rpt"`
}

// DKIM is a selector delegated to the mail provider by a CNAME.
type DKIM struct {
	Selector string `json:"selector"`
	Target   string `json:"target"`
}

// DMARC holds the record's tags; Terraform writes them in this order.
type DMARC struct {
	P     string `json:"p"`
	SP    string `json:"sp"`
	RUA   string `json:"rua"`
	ADKIM string `json:"adkim"`
	ASPF  string `json:"aspf"`
}

type MTASTS struct {
	Mode   string `json:"mode"`
	MaxAge int    `json:"max_age"`
}

type TLSRPT struct {
	RUA string `json:"rua"`
}

// Load returns the embedded declaration, or an error naming every field that
// is unknown, missing or outside its allowed values.
func Load() (Declaration, error) { return parse(mailJSON) }

func parse(data []byte) (Declaration, error) {
	var d Declaration
	// Names match exactly, as they do for Terraform's jsondecode: a mis-cased
	// key is an unknown member here instead of quietly filling the field.
	if err := json.Unmarshal(data, &d, json.RejectUnknownMembers(true)); err != nil {
		return Declaration{}, fmt.Errorf("posture: mail.json: %w", err)
	}
	if err := d.validate(); err != nil {
		return Declaration{}, fmt.Errorf("posture: mail.json: %w", err)
	}
	return d, nil
}

func (d Declaration) validate() error {
	var errs []error
	add := func(err error) {
		if err != nil {
			errs = append(errs, err)
		}
	}
	add(host("domain", d.Domain))
	if len(d.MX) == 0 {
		add(errors.New("mx: want at least one host"))
	}
	for i, mx := range d.MX {
		add(host(fmt.Sprintf("mx[%d]", i), mx))
	}
	if f := strings.Fields(d.SPF); len(f) == 0 || f[0] != "v=spf1" {
		add(fmt.Errorf("spf %q: want a record starting v=spf1", d.SPF))
	}
	add(host("dkim.selector", d.DKIM.Selector))
	add(host("dkim.target", d.DKIM.Target))
	add(oneOf("dmarc.p", d.DMARC.P, "none", "quarantine", "reject"))
	add(oneOf("dmarc.sp", d.DMARC.SP, "none", "quarantine", "reject"))
	add(required("dmarc.rua", d.DMARC.RUA))
	add(oneOf("dmarc.adkim", d.DMARC.ADKIM, "r", "s"))
	add(oneOf("dmarc.aspf", d.DMARC.ASPF, "r", "s"))
	add(oneOf("mta_sts.mode", d.MTASTS.Mode, "testing", "enforce", "none"))
	// RFC 8461 §3.2 caps max_age at 31557600 seconds.
	if d.MTASTS.MaxAge < 1 || d.MTASTS.MaxAge > 31557600 {
		add(fmt.Errorf("mta_sts.max_age %d: want 1 to 31557600 seconds", d.MTASTS.MaxAge))
	}
	add(required("tls_rpt.rua", d.TLSRPT.RUA))
	return errors.Join(errs...)
}

func required(name, v string) error {
	if v == "" {
		return fmt.Errorf("%s: missing", name)
	}
	return nil
}

func oneOf(name, v string, allowed ...string) error {
	if v == "" {
		return required(name, v)
	}
	if slices.Contains(allowed, v) {
		return nil
	}
	return fmt.Errorf("%s %q: want %s or %s", name, v, strings.Join(allowed[:len(allowed)-1], ", "), allowed[len(allowed)-1])
}

func host(name, h string) error {
	switch {
	case h == "":
		return required(name, h)
	case len(h) > 253:
		return fmt.Errorf("%s %q: longer than 253 characters", name, h)
	case !ValidHost(h):
		return fmt.Errorf("%s %q: want a lowercase DNS name", name, h)
	}
	return nil
}

// ValidHost reports whether h is a lowercase DNS name: labels of a-z, 0-9
// and inner hyphens, up to 63 characters each and 253 in all.
func ValidHost(h string) bool {
	if h == "" || len(h) > 253 {
		return false
	}
	for label := range strings.SplitSeq(h, ".") {
		if label == "" || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for _, r := range label {
			if (r < 'a' || r > 'z') && (r < '0' || r > '9') && r != '-' {
				return false
			}
		}
	}
	return true
}
