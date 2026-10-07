package resolve

import (
	"testing"
	"time"
)

const (
	spfJSON    = `{"Status":0,"AD":true,"Answer":[{"name":"vinpatel.org","type":16,"TTL":3600,"data":"\"apple-domain=kMeMA2AbbnslLIHh\""},{"name":"vinpatel.org","type":16,"TTL":3600,"data":"\"v=spf1 include:icloud.com ~all\""}]}`
	dkimJSON   = `{"Status":0,"AD":false,"Answer":[{"name":"sig1._domainkey.vinpatel.org","type":5,"TTL":3600,"data":"sig1.dkim.vinpatel.org.at.icloudmailadmin.com."},{"name":"sig1.dkim.vinpatel.org.at.icloudmailadmin.com","type":16,"TTL":300,"data":"\"v=DKIM1; k=rsa; p=MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA0example\""}]}`
	stsJSON    = `{"Status":0,"AD":true,"Answer":[{"name":"_mta-sts.vinpatel.org","type":16,"TTL":300,"data":"\"v=STSv1; id=3c0a1e1f9b2d4c5e8f7a6b5c4d3e2f1a\""}]}`
	tlsrptJSON = `{"Status":0,"AD":true,"Answer":[{"name":"_smtp._tls.vinpatel.org","type":16,"TTL":300,"data":"\"v=TLSRPTv1; rua=mailto:mail@vinpatel.org\""}]}`
	policyText = "version: STSv1\r\nmode: testing\r\nmx: mx01.mail.icloud.com\r\nmx: mx02.mail.icloud.com\r\nmax_age: 604800\r\n"
)

func fullZone() map[string]string {
	return map[string]string{
		"vinpatel.org":                 spfJSON,
		"sig1._domainkey.vinpatel.org": dkimJSON,
		"_dmarc.vinpatel.org":          dmarcJSON,
		"_mta-sts.vinpatel.org":        stsJSON,
		"_smtp._tls.vinpatel.org":      tlsrptJSON,
	}
}

func TestMail(t *testing.T) {
	u := &upstream{answers: fullZone(), policy: policyText}
	r := newResolver(t, u, epoch(), time.Second, 0)
	got := r.Mail(t.Context(), "vinpatel.org", "sig1")
	want := Mail{SPF: "~all", DKIM: "sig1", DMARC: "reject", MTASTS: "testing", TLSRPT: true, DNSSEC: true}
	if got != want {
		t.Errorf("Mail = %+v\nwant %+v", got, want)
	}
	if n := u.calls.Load(); n != 5 {
		t.Errorf("DNS calls = %d, want 5", n)
	}
	if n := u.policyCalls.Load(); n != 1 {
		t.Errorf("policy calls = %d, want 1", n)
	}
}

func TestMailFollowsDKIMCNAME(t *testing.T) {
	answers := fullZone()
	answers["sig1._domainkey.vinpatel.org"] = `{"Status":0,"AD":true,"Answer":[{"name":"sig1._domainkey.vinpatel.org","type":5,"TTL":3600,"data":"elsewhere.example."}]}`
	r := newResolver(t, &upstream{answers: answers, policy: policyText}, epoch(), time.Second, 0)
	if got := r.Mail(t.Context(), "vinpatel.org", "sig1"); got.DKIM != "" {
		t.Errorf("DKIM = %q with only a CNAME in the answer, want empty", got.DKIM)
	}
}

func TestMailPartsAreIndependent(t *testing.T) {
	answers := fullZone()
	delete(answers, "sig1._domainkey.vinpatel.org")
	delete(answers, "_smtp._tls.vinpatel.org")
	r := newResolver(t, &upstream{answers: answers, policy: policyText}, epoch(), time.Second, 0)
	got := r.Mail(t.Context(), "vinpatel.org", "sig1")
	want := Mail{SPF: "~all", DMARC: "reject", MTASTS: "testing", DNSSEC: true}
	if got != want {
		t.Errorf("Mail = %+v\nwant %+v", got, want)
	}
}

func TestMailDNSSECNeedsEveryAnswerAuthenticated(t *testing.T) {
	answers := fullZone()
	answers["_smtp._tls.vinpatel.org"] = `{"Status":0,"AD":false,"Answer":[{"name":"_smtp._tls.vinpatel.org","type":16,"TTL":300,"data":"\"v=TLSRPTv1; rua=mailto:mail@vinpatel.org\""}]}`
	r := newResolver(t, &upstream{answers: answers, policy: policyText}, epoch(), time.Second, 0)
	got := r.Mail(t.Context(), "vinpatel.org", "sig1")
	if got.DNSSEC || !got.TLSRPT {
		t.Errorf("Mail = %+v, want TLSRPT true and DNSSEC false", got)
	}
}

func TestMailDNSSECIgnoresTheProviderZone(t *testing.T) {
	t.Run("unsigned DKIM answer beside signed ones", func(t *testing.T) {
		r := newResolver(t, &upstream{answers: fullZone(), policy: policyText}, epoch(), time.Second, 0)
		got := r.Mail(t.Context(), "vinpatel.org", "sig1")
		if !got.DNSSEC || got.DKIM != "sig1" {
			t.Errorf("Mail = %+v, want DKIM sig1 and DNSSEC true", got)
		}
	})
	t.Run("only the DKIM answer", func(t *testing.T) {
		answers := map[string]string{"sig1._domainkey.vinpatel.org": dkimJSON}
		r := newResolver(t, &upstream{answers: answers, policy: policyText}, epoch(), time.Second, 0)
		if got := r.Mail(t.Context(), "vinpatel.org", "sig1"); got.DNSSEC {
			t.Errorf("Mail = %+v, want DNSSEC false with nothing from the domain's own zone", got)
		}
	})
}

func TestMailMTASTSNeedsRecordAndPolicy(t *testing.T) {
	t.Run("policy without record", func(t *testing.T) {
		answers := fullZone()
		delete(answers, "_mta-sts.vinpatel.org")
		r := newResolver(t, &upstream{answers: answers, policy: policyText}, epoch(), time.Second, 0)
		if got := r.Mail(t.Context(), "vinpatel.org", "sig1").MTASTS; got != "" {
			t.Errorf("MTASTS = %q, want empty", got)
		}
	})
	t.Run("record without policy", func(t *testing.T) {
		r := newResolver(t, &upstream{answers: fullZone(), policyStatus: 404}, epoch(), time.Second, 0)
		if got := r.Mail(t.Context(), "vinpatel.org", "sig1").MTASTS; got != "" {
			t.Errorf("MTASTS = %q, want empty", got)
		}
	})
	t.Run("redirect is not followed", func(t *testing.T) {
		r := newResolver(t, &upstream{answers: fullZone(), policyStatus: 301}, epoch(), time.Second, 0)
		if got := r.Mail(t.Context(), "vinpatel.org", "sig1").MTASTS; got != "" {
			t.Errorf("MTASTS = %q after a redirect, want empty", got)
		}
	})
}

func TestMailPolicyIsCached(t *testing.T) {
	clk := epoch()
	u := &upstream{answers: fullZone(), policy: policyText}
	r := newResolver(t, u, clk, time.Second, 0)
	r.Mail(t.Context(), "vinpatel.org", "sig1")
	clk.Advance(MailTTL - time.Second)
	r.Mail(t.Context(), "vinpatel.org", "sig1")
	if n := u.policyCalls.Load(); n != 1 {
		t.Errorf("policy calls within TTL = %d, want 1", n)
	}
	clk.Advance(2 * time.Second)
	r.Mail(t.Context(), "vinpatel.org", "sig1")
	if n := u.policyCalls.Load(); n != 2 {
		t.Errorf("policy calls after TTL = %d, want 2", n)
	}
}

func TestMailAgeIsTheOldestAnswer(t *testing.T) {
	clk := epoch()
	u := &upstream{answers: fullZone(), policy: policyText}
	r := newResolver(t, u, clk, time.Second, 0)
	if got := r.Mail(t.Context(), "vinpatel.org", "sig1").Age; got != 0 {
		t.Errorf("fresh Age = %v, want 0", got)
	}
	clk.Advance(14 * time.Minute)
	if got := r.Mail(t.Context(), "vinpatel.org", "sig1").Age; got != 14*time.Minute {
		t.Errorf("Age = %v, want 14m0s", got)
	}
}

func TestMailParsers(t *testing.T) {
	spf := []struct {
		records []string
		want    string
	}{
		{[]string{"v=spf1 include:icloud.com ~all"}, "~all"},
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
	}
	for _, tc := range dmarc {
		if got := dmarcPolicy(tc.records); got != tc.want {
			t.Errorf("dmarcPolicy(%q) = %q, want %q", tc.records, got, tc.want)
		}
	}
	tags := []struct {
		records      []string
		version, tag string
		want         bool
	}{
		{[]string{"v=STSv1; id=20260922T200225Z"}, "v=STSv1", "id", true},
		{[]string{"v=STSv1; id="}, "v=STSv1", "id", false},
		{[]string{"v=STSv2; id=x"}, "v=STSv1", "id", false},
		{[]string{"v=TLSRPTv1; rua=mailto:mail@vinpatel.org"}, "v=TLSRPTv1", "rua", true},
		{[]string{"v=TLSRPTv1"}, "v=TLSRPTv1", "rua", false},
	}
	for _, tc := range tags {
		if got := tagged(tc.records, tc.version, tc.tag); got != tc.want {
			t.Errorf("tagged(%q, %s, %s) = %v, want %v", tc.records, tc.version, tc.tag, got, tc.want)
		}
	}
	modes := []struct{ policy, want string }{
		{policyText, "testing"},
		{"version: STSv1\nmode: ENFORCE\nmx: a.example\nmax_age: 1\n", "enforce"},
		{"version: STSv1\r\nmode: none\r\n", "none"},
		{"version: STSv1\r\nmode: strict\r\n", ""},
		{"mode: testing\r\n", ""},
		{"<!doctype html><title>Parked</title>", ""},
		{"", ""},
	}
	for _, tc := range modes {
		if got := stsMode([]string{tc.policy}); got != tc.want {
			t.Errorf("stsMode(%q) = %q, want %q", tc.policy, got, tc.want)
		}
	}
	if got := stsMode(nil); got != "" {
		t.Errorf("stsMode(nil) = %q", got)
	}
}
