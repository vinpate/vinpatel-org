package resolve

import (
	"reflect"
	"strconv"
	"strings"
	"testing"
	"time"

	"vinpatel.org/site/internal/posture"
)

func declared(t *testing.T) posture.Declaration {
	t.Helper()
	d, err := posture.Load()
	if err != nil {
		t.Fatal(err)
	}
	return d
}

// zone answers the way the domain's DNS does when it publishes what d
// declares. The DKIM answer is unsigned, like iCloud's.
func zone(d posture.Declaration) map[string]string {
	sel := d.DKIM.Selector + "._domainkey." + d.Domain
	return map[string]string{
		d.Domain:                 doh(0, true, txt(d.Domain, "apple-domain=kMeMA2AbbnslLIHh"), txt(d.Domain, d.SPF)),
		sel:                      doh(0, false, cname(sel, d.DKIM.Target+"."), txt(d.DKIM.Target, "v=DKIM1; k=rsa; p=MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA0example")),
		"_dmarc." + d.Domain:     doh(0, true, txt("_dmarc."+d.Domain, dmarcRecord(d))),
		"_mta-sts." + d.Domain:   doh(0, true, txt("_mta-sts."+d.Domain, "v=STSv1; id=3c0a1e1f9b2d4c5e8f7a6b5c4d3e2f1a")),
		"_smtp._tls." + d.Domain: doh(0, true, txt("_smtp._tls."+d.Domain, "v=TLSRPTv1; rua="+d.TLSRPT.RUA)),
	}
}

// dmarcRecord and policy write the declaration out the way Terraform does.
func dmarcRecord(d posture.Declaration) string {
	m := d.DMARC
	return "v=DMARC1; p=" + m.P + "; sp=" + m.SP + "; rua=" + m.RUA + "; adkim=" + m.ADKIM + "; aspf=" + m.ASPF
}

func policy(d posture.Declaration) string {
	lines := []string{"version: STSv1", "mode: " + d.MTASTS.Mode}
	for _, mx := range d.MX {
		lines = append(lines, "mx: "+mx)
	}
	lines = append(lines, "max_age: "+strconv.Itoa(d.MTASTS.MaxAge))
	return strings.Join(lines, "\r\n") + "\r\n"
}

// allTerm is the last mechanism of the declared SPF record.
func allTerm(d posture.Declaration) string {
	f := strings.Fields(d.SPF)
	return f[len(f)-1]
}

// missing is how Cloudflare answers a name deleted from the signed zone:
// no records, no error, the denial authenticated.
var missing = doh(0, true)

// summary keeps only the fields Mail had before it carried its answers.
func summary(m Mail) Mail {
	m.Observed, m.Lookups = posture.Observation{}, Lookups{}
	return m
}

func TestMail(t *testing.T) {
	d := declared(t)
	u := &upstream{answers: zone(d), policy: policy(d)}
	r := newResolver(t, u, epoch(), time.Second, 0)
	got := r.Mail(t.Context(), d.Domain, d.DKIM.Selector)
	want := Mail{SPF: allTerm(d), DKIM: d.DKIM.Selector, DMARC: d.DMARC.P, MTASTS: d.MTASTS.Mode, TLSRPT: true, DNSSEC: true}
	if !reflect.DeepEqual(summary(got), want) {
		t.Errorf("Mail = %+v\nwant %+v", summary(got), want)
	}
	if n := u.calls.Load(); n != 5 {
		t.Errorf("DNS calls = %d, want 5", n)
	}
	if n := u.policyCalls.Load(); n != 1 {
		t.Errorf("policy calls = %d, want 1", n)
	}
}

func TestMailFollowsDKIMCNAME(t *testing.T) {
	d := declared(t)
	sel := d.DKIM.Selector + "._domainkey." + d.Domain
	answers := zone(d)
	answers[sel] = doh(0, true, cname(sel, "elsewhere.example."))
	r := newResolver(t, &upstream{answers: answers, policy: policy(d)}, epoch(), time.Second, 0)
	if got := r.Mail(t.Context(), d.Domain, d.DKIM.Selector); got.DKIM != "" {
		t.Errorf("DKIM = %q with only a CNAME in the answer, want empty", got.DKIM)
	}
}

func TestMailPartsAreIndependent(t *testing.T) {
	d := declared(t)
	answers := zone(d)
	answers[d.DKIM.Selector+"._domainkey."+d.Domain] = missing
	answers["_smtp._tls."+d.Domain] = missing
	r := newResolver(t, &upstream{answers: answers, policy: policy(d)}, epoch(), time.Second, 0)
	got := r.Mail(t.Context(), d.Domain, d.DKIM.Selector)
	want := Mail{SPF: allTerm(d), DMARC: d.DMARC.P, MTASTS: d.MTASTS.Mode, DNSSEC: true}
	if !reflect.DeepEqual(summary(got), want) {
		t.Errorf("Mail = %+v\nwant %+v", summary(got), want)
	}
}

func TestMailDNSSECNeedsEveryAnswerAuthenticated(t *testing.T) {
	d := declared(t)
	answers := zone(d)
	answers["_smtp._tls."+d.Domain] = doh(0, false, txt("_smtp._tls."+d.Domain, "v=TLSRPTv1; rua="+d.TLSRPT.RUA))
	r := newResolver(t, &upstream{answers: answers, policy: policy(d)}, epoch(), time.Second, 0)
	got := r.Mail(t.Context(), d.Domain, d.DKIM.Selector)
	if got.DNSSEC || !got.TLSRPT {
		t.Errorf("Mail = %+v, want TLSRPT true and DNSSEC false", got)
	}
}

func TestMailDNSSECIgnoresTheProviderZone(t *testing.T) {
	d := declared(t)
	t.Run("unsigned DKIM answer beside signed ones", func(t *testing.T) {
		r := newResolver(t, &upstream{answers: zone(d), policy: policy(d)}, epoch(), time.Second, 0)
		got := r.Mail(t.Context(), d.Domain, d.DKIM.Selector)
		if !got.DNSSEC || got.DKIM != d.DKIM.Selector {
			t.Errorf("Mail = %+v, want DKIM %s and DNSSEC true", got, d.DKIM.Selector)
		}
	})
	t.Run("only the DKIM answer", func(t *testing.T) {
		sel := d.DKIM.Selector + "._domainkey." + d.Domain
		answers := map[string]string{sel: zone(d)[sel]}
		for _, name := range []string{d.Domain, "_dmarc." + d.Domain, "_mta-sts." + d.Domain, "_smtp._tls." + d.Domain} {
			answers[name] = doh(2, false)
		}
		r := newResolver(t, &upstream{answers: answers, policy: policy(d)}, epoch(), time.Second, 0)
		if got := r.Mail(t.Context(), d.Domain, d.DKIM.Selector); got.DNSSEC {
			t.Errorf("Mail = %+v, want DNSSEC false with nothing from the domain's own zone", got)
		}
	})
}

func TestMailMTASTSNeedsRecordAndPolicy(t *testing.T) {
	d := declared(t)
	t.Run("policy without record", func(t *testing.T) {
		answers := zone(d)
		delete(answers, "_mta-sts."+d.Domain)
		r := newResolver(t, &upstream{answers: answers, policy: policy(d)}, epoch(), time.Second, 0)
		if got := r.Mail(t.Context(), d.Domain, d.DKIM.Selector).MTASTS; got != "" {
			t.Errorf("MTASTS = %q, want empty", got)
		}
	})
	t.Run("record without policy", func(t *testing.T) {
		r := newResolver(t, &upstream{answers: zone(d), policyStatus: 404}, epoch(), time.Second, 0)
		if got := r.Mail(t.Context(), d.Domain, d.DKIM.Selector).MTASTS; got != "" {
			t.Errorf("MTASTS = %q, want empty", got)
		}
	})
	t.Run("redirect is not followed", func(t *testing.T) {
		r := newResolver(t, &upstream{answers: zone(d), policyStatus: 301}, epoch(), time.Second, 0)
		if got := r.Mail(t.Context(), d.Domain, d.DKIM.Selector).MTASTS; got != "" {
			t.Errorf("MTASTS = %q after a redirect, want empty", got)
		}
	})
}

func TestMailPolicyIsCached(t *testing.T) {
	d := declared(t)
	clk := epoch()
	u := &upstream{answers: zone(d), policy: policy(d)}
	r := newResolver(t, u, clk, time.Second, 0)
	r.Mail(t.Context(), d.Domain, d.DKIM.Selector)
	clk.Advance(MailTTL - time.Second)
	r.Mail(t.Context(), d.Domain, d.DKIM.Selector)
	if n := u.policyCalls.Load(); n != 1 {
		t.Errorf("policy calls within TTL = %d, want 1", n)
	}
	clk.Advance(2 * time.Second)
	r.Mail(t.Context(), d.Domain, d.DKIM.Selector)
	if n := u.policyCalls.Load(); n != 2 {
		t.Errorf("policy calls after TTL = %d, want 2", n)
	}
}

func TestMailAgeIsTheOldestAnswer(t *testing.T) {
	d := declared(t)
	clk := epoch()
	u := &upstream{answers: zone(d), policy: policy(d)}
	r := newResolver(t, u, clk, time.Second, 0)
	if got := r.Mail(t.Context(), d.Domain, d.DKIM.Selector).Age; got != 0 {
		t.Errorf("fresh Age = %v, want 0", got)
	}
	clk.Advance(14 * time.Minute)
	if got := r.Mail(t.Context(), d.Domain, d.DKIM.Selector).Age; got != 14*time.Minute {
		t.Errorf("Age = %v, want 14m0s", got)
	}
}

func TestMailParsers(t *testing.T) {
	spf := []struct {
		records []string
		want    string
	}{
		{[]string{"v=spf1 include:_spf.example ~all"}, "~all"},
		{[]string{"apple-domain=x", "V=SPF1 -ALL"}, "-all"},
		{[]string{"v=spf1 a mx all"}, "+all"},
		{[]string{"v=spf1 ?all"}, "?all"},
		{[]string{"v=spf1 redirect=_spf.example"}, ""},
		{[]string{"v=spf2.0/pra -all"}, ""},
		{nil, ""},
	}
	for _, tc := range spf {
		if got := spfAll(tc.records); got != tc.want {
			t.Errorf("spfAll(%q) = %q, want %q", tc.records, got, tc.want)
		}
	}
	dkim := []struct {
		records []string
		want    bool
	}{
		{[]string{"v=DKIM1; k=rsa; p=MIIB"}, true},
		{[]string{"k=rsa; p=MIIB"}, true},
		{[]string{"v=DKIM1; p="}, false},
		{[]string{"v=DKIM1; k=rsa"}, false},
		{nil, false},
	}
	for _, tc := range dkim {
		if got := dkimPublished(tc.records); got != tc.want {
			t.Errorf("dkimPublished(%q) = %v, want %v", tc.records, got, tc.want)
		}
	}
	dmarc := []struct {
		records []string
		want    string
	}{
		{[]string{"v=DMARC1; p=quarantine"}, "quarantine"},
		{[]string{"v=spf1 -all", "v=DMARC1;p=NONE"}, "none"},
		{[]string{"v=DMARC1; sp=reject"}, ""},
		{[]string{"p=reject"}, ""},
		{[]string{"v=DMARC1; p=bogus"}, ""},
		{[]string{"v=dmarc1; p=reject"}, ""},
		{[]string{"V = DMARC1; p=reject"}, "reject"},
	}
	for _, tc := range dmarc {
		if got := dmarcPolicy(tc.records); got != tc.want {
			t.Errorf("dmarcPolicy(%q) = %q, want %q", tc.records, got, tc.want)
		}
	}
	tags := []struct {
		records            []string
		version, tag, want string
	}{
		{[]string{"v=STSv1; id=20260922T200225Z"}, "v=STSv1", "id", "20260922T200225Z"},
		{[]string{"v=STSv1; id="}, "v=STSv1", "id", ""},
		{[]string{"v=STSv2; id=x"}, "v=STSv1", "id", ""},
		{[]string{"v=TLSRPTv1; rua=mailto:tls@example.org"}, "v=TLSRPTv1", "rua", "mailto:tls@example.org"},
		{[]string{"v=TLSRPTv1"}, "v=TLSRPTv1", "rua", ""},
	}
	for _, tc := range tags {
		if got := tagValue(tc.records, tc.version, tc.tag); got != tc.want {
			t.Errorf("tagValue(%q, %s, %s) = %q, want %q", tc.records, tc.version, tc.tag, got, tc.want)
		}
	}
	policies := []struct {
		policy, mode string
		maxAge       int
	}{
		{"version: STSv1\r\nmode: testing\r\nmx: mx.example\r\nmax_age: 86400\r\n", "testing", 86400},
		{"version: STSv1\nmode: ENFORCE\nmx: a.example\nmax_age: 1\n", "enforce", 1},
		{"version: STSv1\r\nmode: none\r\n", "none", 0},
		{"version: STSv1\r\nmode: strict\r\nmax_age: 86400\r\n", "", 86400},
		{"version: STSv1\r\nmode: testing\r\nmax_age: a week\r\n", "testing", 0},
		{"mode: testing\r\nmax_age: 86400\r\n", "", 0},
		{"<!doctype html><title>Parked</title>", "", 0},
		{"", "", 0},
	}
	for _, tc := range policies {
		if mode, maxAge := stsPolicy([]string{tc.policy}); mode != tc.mode || maxAge != tc.maxAge {
			t.Errorf("stsPolicy(%q) = %q, %d; want %q, %d", tc.policy, mode, maxAge, tc.mode, tc.maxAge)
		}
	}
	if mode, maxAge := stsPolicy(nil); mode != "" || maxAge != 0 {
		t.Errorf("stsPolicy(nil) = %q, %d", mode, maxAge)
	}
	dmarc4 := []struct {
		record            string
		p, sp, pct, tflag string
	}{
		{"v=DMARC1; p=reject; sp=reject; adkim=s", "reject", "reject", "", ""},
		{"v=DMARC1;p=REJECT;pct=0;t=Y", "reject", "", "0", "y"},
		{"v=DMARC1; sp=bogus; pct = 50 ", "", "bogus", "50", ""},
	}
	for _, tc := range dmarc4 {
		if p, sp, pct, tflag := dmarcTags(tc.record); p != tc.p || sp != tc.sp || pct != tc.pct || tflag != tc.tflag {
			t.Errorf("dmarcTags(%q) = %q, %q, %q, %q; want %q, %q, %q, %q", tc.record, p, sp, pct, tflag, tc.p, tc.sp, tc.pct, tc.tflag)
		}
	}
}

func TestMailObservesTheDeclaredZone(t *testing.T) {
	d := declared(t)
	r := newResolver(t, &upstream{answers: zone(d), policy: policy(d)}, epoch(), time.Second, 0)
	got := r.Mail(t.Context(), d.Domain, d.DKIM.Selector).Observed
	want := posture.Observation{
		SPF: posture.Present, DKIM: posture.Present, DMARC: posture.Present,
		MTASTS: posture.Present, Policy: posture.Present, TLSRPT: posture.Present,
		DNSSEC:       true,
		SPFRecords:   1,
		SPFRecord:    d.SPF,
		SPFAll:       allTerm(d),
		DMARCRecords: 1,
		DMARCP:       d.DMARC.P,
		DMARCSP:      d.DMARC.SP,
		STSMode:      d.MTASTS.Mode,
		STSMaxAge:    d.MTASTS.MaxAge,
		TLSRPTRUA:    d.TLSRPT.RUA,
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("Observed = %+v\nwant %+v", got, want)
	}
	for _, c := range posture.Compare(d, got, d.Domain, d.DKIM.Selector).Checks() {
		if c.Match != posture.Matches {
			t.Errorf("%s = %+v against its own declaration, want a match", c.Name, c)
		}
	}
}

func TestMailKeepsTheAnswers(t *testing.T) {
	d := declared(t)
	clk := epoch()
	r := newResolver(t, &upstream{answers: zone(d), policy: policy(d)}, clk, time.Second, 0)
	r.txt(t.Context(), "_dmarc."+d.Domain, MailTTL)
	clk.Advance(2 * time.Minute)
	m := r.Mail(t.Context(), d.Domain, d.DKIM.Selector)
	l := m.Lookups

	sel := d.DKIM.Selector + "._domainkey." + d.Domain
	if l.DKIM.Name != sel || !reflect.DeepEqual(l.DKIM.CNAMEs, []string{d.DKIM.Target + "."}) || len(l.DKIM.Records) != 1 {
		t.Errorf("DKIM answer = %+v, want the selector's name, the CNAME and the key", l.DKIM)
	}
	if l.DKIM.AD || !m.DNSSEC {
		t.Errorf("DKIM ad %v, summary DNSSEC %v; want the unsigned provider answer left out", l.DKIM.AD, m.DNSSEC)
	}
	if !reflect.DeepEqual(l.SPF.Records, []string{"apple-domain=kMeMA2AbbnslLIHh", d.SPF}) || !l.SPF.AD {
		t.Errorf("SPF answer = %+v, want every TXT string at the apex", l.SPF)
	}
	if !reflect.DeepEqual(l.DMARC.Records, []string{dmarcRecord(d)}) || l.DMARC.Name != "_dmarc."+d.Domain {
		t.Errorf("DMARC answer = %+v", l.DMARC)
	}
	if !strings.HasSuffix(l.Policy.Name, "/.well-known/mta-sts.txt") || !reflect.DeepEqual(l.Policy.Records, []string{policy(d)}) {
		t.Errorf("policy answer = %+v, want the URL and the body", l.Policy)
	}
	if l.DMARC.Age != 2*time.Minute || l.SPF.Age != 0 || l.Policy.Age != 0 || m.Age != 2*time.Minute {
		t.Errorf("ages: dmarc %v, spf %v, policy %v, oldest %v; want 2m0s, 0s, 0s, 2m0s", l.DMARC.Age, l.SPF.Age, l.Policy.Age, m.Age)
	}
}

func TestMailTellsAbsentFromUnknown(t *testing.T) {
	d := declared(t)
	name := "_dmarc." + d.Domain
	cases := []struct {
		name   string
		body   string
		want   posture.State
		dnssec bool  // an answered absence counts with its own AD flag; a failure does not count
		calls  int64 // DNS queries once the first answer is five minutes old
	}{
		{"deleted from the signed zone", missing, posture.Absent, true, 5},
		{"name does not exist", doh(3, false), posture.Absent, false, 6},
		{"servfail", doh(2, false), posture.Unknown, true, 6},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			clk := epoch()
			answers := zone(d)
			answers[name] = tc.body
			u := &upstream{answers: answers, policy: policy(d)}
			r := newResolver(t, u, clk, time.Second, 0)
			m := r.Mail(t.Context(), d.Domain, d.DKIM.Selector)
			if m.Observed.DMARC != tc.want || m.DMARC != "" {
				t.Errorf("DMARC state %v, summary %q; want %v and empty", m.Observed.DMARC, m.DMARC, tc.want)
			}
			if m.DNSSEC != tc.dnssec {
				t.Errorf("summary DNSSEC = %v, want %v", m.DNSSEC, tc.dnssec)
			}
			clk.Advance(NegativeTTL - time.Second)
			r.Mail(t.Context(), d.Domain, d.DKIM.Selector)
			if n := u.calls.Load(); n != 5 {
				t.Errorf("DNS calls within five minutes = %d, want 5", n)
			}
			clk.Advance(2 * time.Second)
			r.Mail(t.Context(), d.Domain, d.DKIM.Selector)
			if n := u.calls.Load(); n != tc.calls {
				t.Errorf("DNS calls after five minutes = %d, want %d", n, tc.calls)
			}
		})
	}
	t.Run("stalled upstream", func(t *testing.T) {
		u := &upstream{answers: zone(d), policy: policy(d), delay: time.Second}
		r := newResolver(t, u, epoch(), 20*time.Millisecond, 0)
		if got := r.Mail(t.Context(), d.Domain, d.DKIM.Selector).Observed.DMARC; got != posture.Unknown {
			t.Errorf("DMARC state = %v after a timeout, want unknown", got)
		}
	})
}

func TestMailReadsHowFullyDMARCApplies(t *testing.T) {
	d := declared(t)
	name := "_dmarc." + d.Domain
	cases := []struct {
		name    string
		records []string
		want    posture.Observation
	}{
		{"sampled to nothing", []string{"v=DMARC1; p=reject; pct=0"}, posture.Observation{DMARCRecords: 1, DMARCP: "reject", DMARCPct: "0"}},
		{"two records", []string{"v=DMARC1; p=reject", "v=DMARC1; p=none"}, posture.Observation{DMARCRecords: 2, DMARCP: "reject"}},
		{"none", []string{"v=DMARC1; p=none; t=y"}, posture.Observation{DMARCRecords: 1, DMARCP: "none", DMARCT: "y"}},
		{"broken policy beside a report address", []string{"v=DMARC1; p=bogus; rua=" + d.DMARC.RUA}, posture.Observation{DMARCRecords: 1, DMARCP: "bogus"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var rrs []rr
			for _, rec := range tc.records {
				rrs = append(rrs, txt(name, rec))
			}
			answers := zone(d)
			answers[name] = doh(0, true, rrs...)
			r := newResolver(t, &upstream{answers: answers, policy: policy(d)}, epoch(), time.Second, 0)
			o := r.Mail(t.Context(), d.Domain, d.DKIM.Selector).Observed
			got := posture.Observation{DMARCRecords: o.DMARCRecords, DMARCP: o.DMARCP, DMARCSP: o.DMARCSP, DMARCPct: o.DMARCPct, DMARCT: o.DMARCT}
			if o.DMARC != posture.Present || got != tc.want {
				t.Errorf("DMARC %v %+v, want present %+v", o.DMARC, got, tc.want)
			}
		})
	}
}

func TestMailDKIMNeedsAPublishedKey(t *testing.T) {
	d := declared(t)
	sel := d.DKIM.Selector + "._domainkey." + d.Domain
	target := d.DKIM.Target + "."
	cases := []struct {
		name string
		body string
		want posture.State
	}{
		// iCloud's zone answers a selector it no longer has with NXDOMAIN.
		{"cname to a missing name", doh(3, false, cname(sel, target)), posture.Absent},
		{"target without a key", doh(0, false, cname(sel, target), txt(d.DKIM.Target, "v=DKIM1; k=rsa; p=")), posture.Absent},
		{"target with a key", zone(d)[sel], posture.Present},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			answers := zone(d)
			answers[sel] = tc.body
			r := newResolver(t, &upstream{answers: answers, policy: policy(d)}, epoch(), time.Second, 0)
			m := r.Mail(t.Context(), d.Domain, d.DKIM.Selector)
			if m.Observed.DKIM != tc.want || !reflect.DeepEqual(m.Lookups.DKIM.CNAMEs, []string{target}) {
				t.Errorf("DKIM %v with CNAMEs %q, want %v with %q", m.Observed.DKIM, m.Lookups.DKIM.CNAMEs, tc.want, target)
			}
		})
	}
}

func TestMailPolicyFailureIsUnknown(t *testing.T) {
	d := declared(t)
	t.Run("not found", func(t *testing.T) {
		r := newResolver(t, &upstream{answers: zone(d), policyStatus: 404}, epoch(), time.Second, 0)
		m := r.Mail(t.Context(), d.Domain, d.DKIM.Selector)
		o := m.Observed
		if o.Policy != posture.Unknown || o.MTASTS != posture.Present || o.STSMode != "" || m.Lookups.Policy.Records != nil {
			t.Errorf("policy %v, record %v, mode %q, body %q; want unknown beside a present record", o.Policy, o.MTASTS, o.STSMode, m.Lookups.Policy.Records)
		}
	})
	t.Run("a page instead of a policy", func(t *testing.T) {
		r := newResolver(t, &upstream{answers: zone(d), policy: "<!doctype html><title>Parked</title>"}, epoch(), time.Second, 0)
		o := r.Mail(t.Context(), d.Domain, d.DKIM.Selector).Observed
		if o.Policy != posture.Present || o.STSMode != "" {
			t.Errorf("policy %v, mode %q; want present with no mode", o.Policy, o.STSMode)
		}
	})
}

func TestMailCountsSPFRecords(t *testing.T) {
	d := declared(t)
	answers := zone(d)
	answers[d.Domain] = doh(0, true, txt(d.Domain, d.SPF), txt(d.Domain, "v=spf1 -all"))
	answers["_smtp._tls."+d.Domain] = doh(0, true, txt("_smtp._tls."+d.Domain, "v=TLSRPTv1"))
	r := newResolver(t, &upstream{answers: answers, policy: policy(d)}, epoch(), time.Second, 0)
	o := r.Mail(t.Context(), d.Domain, d.DKIM.Selector).Observed
	if o.SPF != posture.Present || o.SPFRecords != 2 || o.SPFRecord != d.SPF {
		t.Errorf("SPF %v, %d records, first %q; want present, 2, the declared one", o.SPF, o.SPFRecords, o.SPFRecord)
	}
	if o.TLSRPT != posture.Absent {
		t.Errorf("TLSRPT = %v for a record with no rua, want absent", o.TLSRPT)
	}
}
