package posture

import (
	"fmt"
	"strings"
	"testing"
)

func load(t *testing.T) Declaration {
	t.Helper()
	d, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	return d
}

// allTerm is the last mechanism of the declared SPF record.
func allTerm(d Declaration) string {
	f := strings.Fields(d.SPF)
	return f[len(f)-1]
}

// published is what DNS shows when it carries exactly what d declares.
func published(d Declaration) Observation {
	return Observation{
		SPF: Present, DKIM: Present, DMARC: Present, MTASTS: Present, Policy: Present, TLSRPT: Present,
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
}

func compare(t *testing.T, d Declaration, edit func(o *Observation)) Report {
	t.Helper()
	o := published(d)
	if edit != nil {
		edit(&o)
	}
	return Compare(d, o, d.Domain, d.DKIM.Selector)
}

func TestAgreementConfirms(t *testing.T) {
	d := load(t)
	d.DMARC.P = "reject"
	r := compare(t, d, nil)
	if r.Verdict != Confirmed || !r.Declared {
		t.Fatalf("verdict %v, declared %v; want confirmed against a declaration", r.Verdict, r.Declared)
	}
	for _, c := range r.Checks() {
		if c.State != Present || c.Match != Matches {
			t.Errorf("%s = %+v, want present and matching", c.Name, c)
		}
	}
	if r.DNSSEC != Present || !r.Authenticated {
		t.Errorf("dnssec %v, authenticated %v; want present and authenticated", r.DNSSEC, r.Authenticated)
	}
}

func TestVerdictReadsDMARCAlone(t *testing.T) {
	d := load(t)
	d.DMARC.P = "reject"
	// Every case starts from DNS publishing the declaration with p=reject.
	cases := []struct {
		name  string
		decl  string
		edit  func(o *Observation)
		want  Verdict
		match Match
	}{
		{"observed none against declared reject", "reject", func(o *Observation) { o.DMARCP = "none" }, Weaker, Differs},
		{"observed quarantine", "reject", func(o *Observation) { o.DMARCP = "quarantine" }, Weaker, Differs},
		{"declared none, observed reject", "none", nil, Confirmed, Differs},
		{"every lookup failed", "reject", func(o *Observation) { *o = Observation{} }, Unconfirmed, NotCompared},
		{"dmarc answered absent", "reject", func(o *Observation) { o.DMARC, o.DMARCRecords, o.DMARCP, o.DMARCSP = Absent, 0, "", "" }, Weaker, Differs},
		{"dmarc lookup failed", "reject", func(o *Observation) { o.DMARC, o.DMARCRecords, o.DMARCP, o.DMARCSP = Unknown, 0, "", "" }, Unconfirmed, NotCompared},
		{"reject sampled at pct=0", "reject", func(o *Observation) { o.DMARCPct = "0" }, Weaker, Differs},
		{"reject with pct=100 written out", "reject", func(o *Observation) { o.DMARCPct = "100" }, Confirmed, Matches},
		{"reject with an unparseable pct", "reject", func(o *Observation) { o.DMARCPct = "most" }, Weaker, Differs},
		{"reject flagged t=y", "reject", func(o *Observation) { o.DMARCT = "y" }, Weaker, Differs},
		{"reject flagged t=n", "reject", func(o *Observation) { o.DMARCT = "n" }, Confirmed, Matches},
		{"reject with an unknown t value", "reject", func(o *Observation) { o.DMARCT = "yes" }, Weaker, Differs},
		{"reject with an invalid sp", "reject", func(o *Observation) { o.DMARCSP = "bogus" }, Weaker, Differs},
		{"two dmarc records", "reject", func(o *Observation) { o.DMARCRecords = 2 }, Weaker, Differs},
		{"a record without p", "reject", func(o *Observation) { o.DMARCP = "" }, Weaker, Differs},
		{"a record with an invalid p", "reject", func(o *Observation) { o.DMARCP = "bogus" }, Weaker, Differs},
		{"reject with the dkim lookup failed", "reject", func(o *Observation) { o.DKIM = Unknown }, Confirmed, Matches},
		{"reject with no dkim key", "reject", func(o *Observation) { o.DKIM = Absent }, Confirmed, Matches},
		{"none with the dkim lookup failed", "reject", func(o *Observation) { o.DMARCP, o.DKIM = "none", Unknown }, Weaker, Differs},
		{"reject with nothing else answered", "reject", func(o *Observation) {
			o.SPF, o.DKIM, o.MTASTS, o.Policy, o.TLSRPT, o.DNSSEC = Unknown, Unknown, Unknown, Unknown, Unknown, false
		}, Confirmed, Matches},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			o := published(d)
			if tc.edit != nil {
				tc.edit(&o)
			}
			decl := d
			decl.DMARC.P = tc.decl
			r := Compare(decl, o, d.Domain, d.DKIM.Selector)
			if r.Verdict != tc.want {
				t.Errorf("verdict = %v, want %v", r.Verdict, tc.want)
			}
			if r.DMARC.Match != tc.match {
				t.Errorf("dmarc match = %v, want %v", r.DMARC.Match, tc.match)
			}
		})
	}
}

func TestEveryLookupFailed(t *testing.T) {
	d := load(t)
	r := Compare(d, Observation{}, d.Domain, d.DKIM.Selector)
	if r.Verdict != Unconfirmed {
		t.Errorf("verdict = %v, want unconfirmed", r.Verdict)
	}
	for _, c := range r.Checks() {
		if c.State != Unknown || c.Match != NotCompared || c.Observed != "" {
			t.Errorf("%s = %+v, want unknown, not compared, nothing observed", c.Name, c)
		}
		if c.Declared == "" {
			t.Errorf("%s carries no declared value; /trace shows it as intent", c.Name)
		}
	}
	if r.DNSSEC != Unknown {
		t.Errorf("dnssec = %v with nothing answered, want unknown", r.DNSSEC)
	}
}

func TestDNSSECIsReportedNotCompared(t *testing.T) {
	d := load(t)
	d.DMARC.P = "reject"
	r := compare(t, d, func(o *Observation) { o.DNSSEC = false })
	if r.DNSSEC != Present || r.Authenticated {
		t.Errorf("dnssec %v, authenticated %v; want present and not authenticated", r.DNSSEC, r.Authenticated)
	}
	if r.Verdict != Confirmed {
		t.Errorf("verdict = %v, want confirmed whatever the resolver says of DNSSEC", r.Verdict)
	}
}

func TestDNSSECNeedsAnAnswerFromTheOwnZone(t *testing.T) {
	d := load(t)
	cases := []struct {
		name string
		o    Observation
		want State
	}{
		{"only the provider-zone dkim answer", Observation{DKIM: Present}, Unknown},
		{"only spf", Observation{SPF: Present}, Present},
		{"only dmarc, answered absent", Observation{DMARC: Absent}, Present},
		{"only mta-sts", Observation{MTASTS: Present}, Present},
		{"only tls-rpt, answered absent", Observation{TLSRPT: Absent}, Present},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := Compare(d, tc.o, d.Domain, d.DKIM.Selector).DNSSEC; got != tc.want {
				t.Errorf("dnssec = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestChecksThatDiffer(t *testing.T) {
	d := load(t)
	d.DMARC.P = "reject"
	otherMode := map[string]string{"testing": "enforce", "enforce": "testing", "none": "testing"}[d.MTASTS.Mode]
	otherAge := d.MTASTS.MaxAge + 1
	stsDeclared := fmt.Sprintf("%s max_age %d", d.MTASTS.Mode, d.MTASTS.MaxAge)
	cases := []struct {
		name     string
		edit     func(o *Observation)
		check    func(r Report) Check
		observed string
		declared string
	}{
		{"spf with another include and the same all term", func(o *Observation) { o.SPFRecord = "v=spf1 include:_spf.example ~all" },
			func(r Report) Check { return r.SPF }, "v=spf1 include:_spf.example ~all", d.SPF},
		{"two spf records", func(o *Observation) { o.SPFRecords = 2 },
			func(r Report) Check { return r.SPF }, "2 records", d.SPF},
		{"dmarc none", func(o *Observation) { o.DMARCP = "none" },
			func(r Report) Check { return r.DMARC }, "p=none", "reject"},
		{"dmarc sampled", func(o *Observation) { o.DMARCPct = "50" },
			func(r Report) Check { return r.DMARC }, "p=reject pct=50", "reject"},
		{"dmarc flagged and with a broken sp", func(o *Observation) { o.DMARCT, o.DMARCSP = "y", "bogus" },
			func(r Report) Check { return r.DMARC }, "p=reject sp=bogus t=y", "reject"},
		{"dmarc two records", func(o *Observation) { o.DMARCRecords = 2 },
			func(r Report) Check { return r.DMARC }, "2 records", "reject"},
		{"dmarc without p", func(o *Observation) { o.DMARCP = "" },
			func(r Report) Check { return r.DMARC }, "p missing", "reject"},
		{"mta-sts mode", func(o *Observation) { o.STSMode = otherMode },
			func(r Report) Check { return r.MTASTS }, fmt.Sprintf("%s max_age %d", otherMode, d.MTASTS.MaxAge), stsDeclared},
		{"mta-sts max age", func(o *Observation) { o.STSMaxAge = otherAge },
			func(r Report) Check { return r.MTASTS }, fmt.Sprintf("%s max_age %d", d.MTASTS.Mode, otherAge), stsDeclared},
		{"tls-rpt address", func(o *Observation) { o.TLSRPTRUA = "mailto:tls@example.org" },
			func(r Report) Check { return r.TLSRPT }, "mailto:tls@example.org", d.TLSRPT.RUA},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c := tc.check(compare(t, d, tc.edit))
			if c.State != Present || c.Match != Differs || c.Observed != tc.observed || c.Declared != tc.declared {
				t.Errorf("check = %+v\nwant present, differing, observed %q, declared %q", c, tc.observed, tc.declared)
			}
		})
	}
}

func TestSPFComparesTheWholeRecordLoosely(t *testing.T) {
	d := load(t)
	r := compare(t, d, func(o *Observation) { o.SPFRecord = strings.ToUpper(strings.ReplaceAll(d.SPF, " ", "   ")) })
	if r.SPF.Match != Matches {
		t.Errorf("spf = %+v, want a match across case and spacing", r.SPF)
	}
}

func TestMatchingChecksReadAsTheRowShowsThem(t *testing.T) {
	d := load(t)
	r := compare(t, d, nil)
	want := map[string]string{"spf": allTerm(d), "dkim": d.DKIM.Selector, "dmarc": "p=" + d.DMARC.P, "mta-sts": d.MTASTS.Mode, "tls-rpt": ""}
	for _, c := range r.Checks() {
		if c.Observed != want[c.Name] {
			t.Errorf("%s observed = %q, want %q", c.Name, c.Observed, want[c.Name])
		}
	}
}

func TestAbsentChecksDiffer(t *testing.T) {
	d := load(t)
	r := compare(t, d, func(o *Observation) { o.DKIM, o.TLSRPT, o.TLSRPTRUA = Absent, Absent, "" })
	for _, c := range []Check{r.DKIM, r.TLSRPT} {
		if c.State != Absent || c.Match != Differs || c.Declared == "" || c.Observed != "" {
			t.Errorf("%s = %+v, want absent, differing, with the declared value and nothing observed", c.Name, c)
		}
	}
}

func TestMTASTSNeedsRecordAndValidPolicy(t *testing.T) {
	d := load(t)
	cases := []struct {
		name string
		edit func(o *Observation)
		want State
	}{
		{"record answered absent", func(o *Observation) { o.MTASTS = Absent }, Absent},
		{"record lookup failed", func(o *Observation) { o.MTASTS = Unknown }, Unknown},
		{"policy fetch failed", func(o *Observation) { o.Policy, o.STSMode, o.STSMaxAge = Unknown, "", 0 }, Unknown},
		{"policy fetched but invalid", func(o *Observation) { o.STSMode = "" }, Unknown},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := compare(t, d, tc.edit)
			if r.MTASTS.State != tc.want {
				t.Errorf("mta-sts state = %v, want %v", r.MTASTS.State, tc.want)
			}
		})
	}
}

func TestSelectorOverrideDiffers(t *testing.T) {
	d := load(t)
	r := Compare(d, published(d), d.Domain, "other")
	if r.DKIM.Match != Differs || r.DKIM.Observed != "other" || r.DKIM.Declared != d.DKIM.Selector {
		t.Errorf("dkim = %+v, want the configured selector differing from the declared one", r.DKIM)
	}
}

func TestOtherHostHasNoDeclaration(t *testing.T) {
	d := load(t)
	d.DMARC.P = "reject"
	o := published(d)
	o.SPFRecord = "v=spf1 -all"
	r := Compare(d, o, "example.org", d.DKIM.Selector)
	if r.Declared || r.Verdict != Confirmed {
		t.Fatalf("declared %v, verdict %v; want no declaration and the verdict from DNS", r.Declared, r.Verdict)
	}
	for _, c := range r.Checks() {
		if c.Match != NotCompared || c.Declared != "" {
			t.Errorf("%s = %+v, want nothing compared and nothing declared", c.Name, c)
		}
	}
	if r.SPF.Observed != allTerm(d) {
		t.Errorf("spf observed = %q, want the short form when nothing is compared", r.SPF.Observed)
	}
}
