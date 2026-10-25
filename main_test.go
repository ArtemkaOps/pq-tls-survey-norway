package main

import (
	"context"
	"crypto/tls"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestCymruOriginName(t *testing.T) {
	cases := map[string]string{
		"104.16.123.96":        "96.123.16.104.origin.asn.cymru.com",
		"2606:4700::6810:7b60": "0.6.b.7.0.1.8.6.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.7.4.6.0.6.2.origin6.asn.cymru.com",
	}
	for in, want := range cases {
		if got := cymruOriginName(net.ParseIP(in)); got != want {
			t.Errorf("cymruOriginName(%s) = %s, want %s", in, got, want)
		}
	}
}

func fakeTXT(records map[string][]string) txtLookup {
	return func(_ context.Context, name string) ([]string, error) {
		if r, ok := records[name]; ok {
			return r, nil
		}
		return nil, errors.New("no such host")
	}
}

func TestLookupASN(t *testing.T) {
	lookup := fakeTXT(map[string][]string{
		"96.123.16.104.origin.asn.cymru.com": {"13335 | 104.16.0.0/13 | US | arin | 2014-03-28"},
		"AS13335.asn.cymru.com":              {"13335 | US | arin | 2010-07-14 | CLOUDFLARENET, US"},
		"1.0.0.10.origin.asn.cymru.com":      {"should not be asked"},
		"5.4.3.2.origin.asn.cymru.com":       {"224 3307 | 2.3.0.0/16 | NO | ripencc | 2010-01-01"},
		"AS224.asn.cymru.com":                {"224 | NO | ripencc | 1990-01-01 | UNINETT Sikt, NO"},
	})
	asn, name, country := lookupASN(lookup, "104.16.123.96")
	if asn != "13335" || name != "CLOUDFLARENET, US" || country != "US" {
		t.Errorf("got %q %q %q", asn, name, country)
	}
	asn, name, country = lookupASN(lookup, "2.3.4.5")
	if asn != "224" || name != "UNINETT Sikt, NO" || country != "NO" {
		t.Errorf("multi-origin: got %q %q %q", asn, name, country)
	}
	if asn, _, _ := lookupASN(lookup, "10.0.0.1"); asn != "" {
		t.Errorf("private IP should be skipped, got %q", asn)
	}
	if asn, _, _ := lookupASN(lookup, "127.0.0.1"); asn != "" {
		t.Errorf("loopback should be skipped, got %q", asn)
	}
	if asn, _, _ := lookupASN(lookup, "8.8.8.8"); asn != "" {
		t.Errorf("unknown IP should give empty result, got %q", asn)
	}
}

func TestDetectCDN(t *testing.T) {
	h := func(kv ...string) http.Header {
		out := http.Header{}
		for i := 0; i < len(kv); i += 2 {
			out.Set(kv[i], kv[i+1])
		}
		return out
	}
	cases := []struct {
		name          string
		headers       http.Header
		cname, asName string
		want          string
	}{
		{"cf-ray", h("Cf-Ray", "8a1b-OSL"), "", "", "Cloudflare"},
		{"server cloudflare", h("Server", "cloudflare"), "", "", "Cloudflare"},
		{"azure", h("X-Azure-Ref", "0abc"), "", "", "Azure Front Door"},
		{"cloudfront", h("X-Amz-Cf-Id", "xyz"), "", "", "Amazon CloudFront"},
		{"akamai server", h("Server", "AkamaiGHost"), "", "", "Akamai"},
		{"fastly", h("X-Served-By", "cache-osl6521-OSL"), "", "", "Fastly"},
		{"imperva", h("X-Iinfo", "1-2-3"), "", "", "Imperva"},
		{"akamai cname", nil, "www.nav.no.edgekey.net", "", "Akamai"},
		{"azure cname", h("Server", "Apache"), "foo.azurefd.net", "", "Azure Front Door"},
		{"akamai asn", nil, "", "AKAMAI-AS, US", "Akamai"},
		{"plain apache", h("Server", "Apache"), "", "UNINETT Sikt, NO", ""},
		{"nothing", nil, "", "", ""},
		// Cases seen in the real survey on 2026-10-25
		{"cloudfront header on akamai IP (DNB)", h("X-Amz-Cf-Id", "x"), "", "AKAMAI-ASN1 - Akamai International B.V., NL", "Akamai"},
		{"akamai node inside an ISP (NRK)", nil, "www.nrk.no.edgesuite.net", "Enivest-AS - Enivest AS, NO", "Akamai"},
		{"azure front door", h("X-Azure-Ref", "x"), "a.z01.azurefd.net", "MICROSOFT-CORP-MSN-AS-BLOCK - Microsoft Corporation, US", "Azure Front Door"},
		{"azure without front door (Politiet)", nil, "", "MICROSOFT-CORP-MSN-AS-BLOCK - Microsoft Corporation, US", "Microsoft Azure"},
		{"cloudfront", h("X-Amz-Cf-Id", "x"), "d1.cloudfront.net", "AMAZON-02 - Amazon.com, Inc., US", "Amazon CloudFront"},
		{"google cloud (SSB)", nil, "", "GOOGLE-CLOUD-PLATFORM - Google LLC, US", "Google Cloud"},
		{"fastly", h("X-Served-By", "cache-osl"), "dualstack.t.sni.global.fastly.net", "FASTLY - Fastly, Inc., US", "Fastly"},
	}
	for _, c := range cases {
		got, evidence := detectCDN(c.headers, c.cname, c.asName)
		if got != c.want {
			t.Errorf("%s: got %q, want %q", c.name, got, c.want)
		}
		if (got == "") != (evidence == "") {
			t.Errorf("%s: evidence %q does not match result %q", c.name, evidence, got)
		}
	}

	// cf-ray header from an IP in the agency's own network (Statens vegvesen):
	// the TLS connection ends there, Cloudflare is only further behind.
	got, evidence := detectCDN(h("Cf-Ray", "x"), "vegvesen.no", "STATENS-VEGVESEN - Statens Vegvesen, NO")
	if got != "" || !strings.Contains(evidence, "further behind") {
		t.Errorf("upstream cf-ray: got %q, %q", got, evidence)
	}
}

func TestParseSites(t *testing.T) {
	data := []byte("\xef\xbb\xbf# comment\r\nPublic services | NAV | www.nav.no\r\n\r\nwww.example.no\r\n")
	sites, err := parseSites(data)
	if err != nil || len(sites) != 2 {
		t.Fatalf("got %v %v", sites, err)
	}
	if sites[0] != (Site{"Public services", "NAV", "www.nav.no"}) || sites[1].Group != "Other" {
		t.Errorf("unexpected %v", sites)
	}
	if _, err := parseSites([]byte("a | b\n")); err == nil {
		t.Error("expected error for 2-field line")
	}
}

// startTLS starts a local HTTPS server with the given TLS settings and response header.
func startTLS(t *testing.T, cfg *tls.Config, header, value string) string {
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if header != "" {
			w.Header().Set(header, value)
		}
		if r.Method == http.MethodHead {
			w.WriteHeader(http.StatusMethodNotAllowed) // force the GET fallback
			return
		}
		w.Write([]byte("ok"))
	}))
	srv.TLS = cfg
	srv.StartTLS()
	t.Cleanup(srv.Close)
	return strings.TrimPrefix(srv.URL, "https://")
}

func TestCheckEndToEnd(t *testing.T) {
	lookupTXT = fakeTXT(nil)

	pqHost := startTLS(t, &tls.Config{}, "Cf-Ray", "test-OSL")
	r := check(Site{"G", "PQ behind Cloudflare", pqHost})
	if !r.Reachable || !r.PQ || r.TLSVersion != "TLS 1.3" || r.CDN != "Cloudflare" || r.IP != "127.0.0.1" {
		t.Errorf("pq site: %+v", r)
	}
	if !strings.Contains(r.CertIssuer, "Acme Co") {
		t.Errorf("cert issuer not recorded: %q", r.CertIssuer)
	}

	classicHost := startTLS(t, &tls.Config{CurvePreferences: []tls.CurveID{tls.X25519, tls.CurveP256}}, "Server", "Apache")
	r = check(Site{"G", "classic", classicHost})
	if !r.Reachable || r.PQ || r.CDN != "" || r.Server != "Apache" || status(r) != "no" {
		t.Errorf("classic site: %+v", r)
	}

	tls12Host := startTLS(t, &tls.Config{MaxVersion: tls.VersionTLS12}, "", "")
	r = check(Site{"G", "tls12", tls12Host})
	if !r.Reachable || r.PQ || status(r) != "no (TLS 1.2, no TLS 1.3)" {
		t.Errorf("tls12 site: %+v", r)
	}

	r = check(Site{"G", "closed", "127.0.0.1:9"})
	if r.Reachable || status(r) != "unreachable" {
		t.Errorf("closed port: %+v", r)
	}
}

func TestCommonIssuer(t *testing.T) {
	mk := func(issuers ...string) []Result {
		var rs []Result
		for _, i := range issuers {
			rs = append(rs, Result{Reachable: true, CertIssuer: i})
		}
		return append(rs, Result{Reachable: false})
	}
	// Normal network: many different certificate authorities
	normal := mk("Let's Encrypt / R11", "DigiCert Inc / DigiCert Global G2 TLS RSA SHA256 2020 CA1",
		"Google Trust Services / WE1", "Buypass AS-983163327 / Buypass Class 2 CA 5", "Let's Encrypt / R10",
		"Sectigo Limited / Sectigo RSA Domain Validation Secure Server CA", "Google Trust Services / WE1")
	issuer, count, reachable := commonIssuer(normal)
	if reachable != 7 || count != 2 || inspectionSuspected(count, reachable) {
		t.Errorf("normal network flagged: %s %d/%d", issuer, count, reachable)
	}
	// Inspected network: the firewall signs everything
	fw := mk("Fortinet / FortiGate CA", "Fortinet / FortiGate CA", "Fortinet / FortiGate CA",
		"Fortinet / FortiGate CA", "Fortinet / FortiGate CA", "Fortinet / FortiGate CA", "Let's Encrypt / R11")
	issuer, count, reachable = commonIssuer(fw)
	if issuer != "Fortinet / FortiGate CA" || !inspectionSuspected(count, reachable) {
		t.Errorf("inspection not detected: %s %d/%d", issuer, count, reachable)
	}
	if inspectionSuspected(3, 3) {
		t.Error("too few sites must not trigger the warning")
	}
}

func TestCleanLabel(t *testing.T) {
	cases := map[string]string{"": "home", "  \r\n": "home", "School\r\n": "school",
		"skole Eid": "skole-eid", "æøå": "other", "home_2": "home-2"}
	for in, want := range cases {
		if got := cleanLabel(in); got != want {
			t.Errorf("cleanLabel(%q) = %q, want %q", in, got, want)
		}
	}
}
