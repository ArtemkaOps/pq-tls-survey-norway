// pqcheck: checks which websites accept post-quantum TLS key exchange (hybrid X25519MLKEM768)
// and who terminates the TLS connection (CDN or network operator).
//
// Site list: sites.txt next to the program (one site per line: group | organization | host).
// If sites.txt is missing, it is created with the default list.
// Output: a table in the console and pq_survey_<date>_<network>.csv next to the program.
//
// For each site:
//  1. TLS handshake with classic key exchange only (X25519, P-256, P-384):
//     is the site reachable, which TLS version, which IP address answered
//  2. TLS handshake with X25519MLKEM768 only, to the same IP: is post-quantum key exchange accepted
//  3. HTTPS HEAD request to the same IP: response headers (Server, CDN markers such as cf-ray)
//  4. DNS: CNAME of the host and the autonomous system (AS) that announces the IP (Team Cymru DNS)
//  5. Issuer of the server certificate. If most sites show the same issuer, the network
//     probably inspects HTTPS traffic (TLS inspection) and the results are not valid.
//
// Certificates are not verified and no data is sent: only the key exchange is measured.
//
// Flags:
//
//	-network <label>  label written to the CSV, e.g. home or colab (default: home)
//	-nowait           do not wait for Enter before exiting
package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/csv"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"text/tabwriter"
	"time"
)

const (
	version = "1.3"
	timeout = 10 * time.Second
)

type Site struct {
	Group, Org, Host string
}

type Result struct {
	Site
	Reachable  bool
	TLSVersion string
	PQ         bool
	IP         string
	Server     string
	CNAME      string
	ASN        string
	ASName     string
	IPCountry  string
	CDN        string
	Evidence   string
	CertIssuer string
	Error      string
}

// Default list: national public-sector sites plus one control site.
// Edit sites.txt to check other sites.
var defaultSites = []Site{
	{"Defence & security", "Forsvaret", "www.forsvaret.no"},
	{"Defence & security", "FFI - Forsvarets forskningsinstitutt", "www.ffi.no"},
	{"Defence & security", "Forsvarsmateriell", "www.fma.no"},
	{"Defence & security", "Forsvarsbygg", "www.forsvarsbygg.no"},
	{"Defence & security", "NSM - Nasjonal sikkerhetsmyndighet", "nsm.no"},
	{"Defence & security", "PST", "www.pst.no"},
	{"Defence & security", "Politiet", "www.politiet.no"},
	{"Defence & security", "DSB - samfunnssikkerhet og beredskap", "www.dsb.no"},

	{"Public services", "Regjeringen", "www.regjeringen.no"},
	{"Public services", "Stortinget", "www.stortinget.no"},
	{"Public services", "NAV", "www.nav.no"},
	{"Public services", "Skatteetaten", "www.skatteetaten.no"},
	{"Public services", "Altinn", "www.altinn.no"},
	{"Public services", "ID-porten (login)", "login.idporten.no"},
	{"Public services", "Helsenorge", "www.helsenorge.no"},
	{"Public services", "Norge.no", "www.norge.no"},
	{"Public services", "Statens vegvesen", "www.vegvesen.no"},
	{"Public services", "Brønnøysundregistrene", "www.brreg.no"},
	{"Public services", "Digdir", "www.digdir.no"},
	{"Public services", "Nkom", "www.nkom.no"},
	{"Public services", "SSB", "www.ssb.no"},

	{"Control", "Cloudflare PQ test", "pq.cloudflareresearch.com"},
}

// ---------- site list ----------

func writeDefaultSites(path string) error {
	var b strings.Builder
	b.WriteString("# One site per line: group | organization | host\r\n")
	b.WriteString("# Lines starting with # are ignored. Keep the Control line: it shows whether the check itself works.\r\n")
	for _, s := range defaultSites {
		fmt.Fprintf(&b, "%s | %s | %s\r\n", s.Group, s.Org, s.Host)
	}
	return os.WriteFile(path, []byte(b.String()), 0o644)
}

func parseSites(data []byte) ([]Site, error) {
	data = bytes.TrimPrefix(data, []byte("\xef\xbb\xbf")) // UTF-8 BOM from Notepad
	var sites []Site
	sc := bufio.NewScanner(bytes.NewReader(data))
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		parts := strings.Split(line, "|")
		for i := range parts {
			parts[i] = strings.TrimSpace(parts[i])
		}
		switch len(parts) {
		case 3:
			sites = append(sites, Site{parts[0], parts[1], parts[2]})
		case 1:
			sites = append(sites, Site{"Other", parts[0], parts[0]})
		default:
			return nil, fmt.Errorf("sites.txt: cannot read line %q", line)
		}
	}
	if len(sites) == 0 {
		return nil, errors.New("sites.txt has no sites")
	}
	return sites, nil
}

func loadSites(path string) ([]Site, string, error) {
	data, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		if werr := writeDefaultSites(path); werr != nil {
			return defaultSites, "built-in list", nil
		}
		return defaultSites, "built-in list (saved to sites.txt)", nil
	}
	if err != nil {
		return nil, "", err
	}
	sites, err := parseSites(data)
	return sites, "sites.txt", err
}

// ---------- TLS and HTTP ----------

func splitHostPort(s string) (host, port string) {
	if h, p, err := net.SplitHostPort(s); err == nil {
		return h, p
	}
	return s, "443"
}

func handshake(serverName, addr string, curves []tls.CurveID, minVer uint16) (tls.ConnectionState, string, error) {
	cfg := &tls.Config{
		ServerName:         serverName,
		InsecureSkipVerify: true, // only the key exchange matters here
		CurvePreferences:   curves,
		MinVersion:         minVer,
		NextProtos:         []string{"http/1.1"},
	}
	conn, err := tls.DialWithDialer(&net.Dialer{Timeout: timeout}, "tcp", addr, cfg)
	if err != nil {
		return tls.ConnectionState{}, "", err
	}
	defer conn.Close()
	ip := ""
	if ta, ok := conn.RemoteAddr().(*net.TCPAddr); ok {
		ip = ta.IP.String()
	}
	return conn.ConnectionState(), ip, nil
}

func versionName(v uint16) string {
	switch v {
	case tls.VersionTLS13:
		return "TLS 1.3"
	case tls.VersionTLS12:
		return "TLS 1.2"
	case tls.VersionTLS11:
		return "TLS 1.1"
	case tls.VersionTLS10:
		return "TLS 1.0"
	}
	return ""
}

// fetchHeaders sends HEAD (and GET if HEAD is refused) to the given IP and returns the response headers.
func fetchHeaders(host, ip, port string) http.Header {
	dialer := &net.Dialer{Timeout: timeout}
	client := &http.Client{
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
				return dialer.DialContext(ctx, "tcp", net.JoinHostPort(ip, port))
			},
			TLSClientConfig:     &tls.Config{ServerName: host, InsecureSkipVerify: true},
			TLSHandshakeTimeout: timeout,
		},
		Timeout:       timeout,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
	url := "https://" + host + "/"
	if port != "443" {
		url = "https://" + net.JoinHostPort(host, port) + "/"
	}
	var last http.Header
	for _, method := range []string{"HEAD", "GET"} {
		req, err := http.NewRequest(method, url, nil)
		if err != nil {
			return last
		}
		req.Header.Set("User-Agent", "pqcheck/"+version+" (post-quantum TLS survey)")
		resp, err := client.Do(req)
		if err != nil {
			continue
		}
		io.Copy(io.Discard, io.LimitReader(resp.Body, 64<<10))
		resp.Body.Close()
		last = resp.Header
		if resp.StatusCode != http.StatusMethodNotAllowed && resp.StatusCode != http.StatusNotImplemented {
			return last
		}
	}
	return last
}

// ---------- DNS: CNAME and autonomous system ----------

type txtLookup func(ctx context.Context, name string) ([]string, error)

var lookupTXT txtLookup = net.DefaultResolver.LookupTXT

func lookupCNAME(host string) string {
	if net.ParseIP(host) != nil {
		return ""
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	c, err := net.DefaultResolver.LookupCNAME(ctx, host)
	if err != nil {
		return ""
	}
	c = strings.TrimSuffix(strings.ToLower(c), ".")
	if c == strings.TrimSuffix(strings.ToLower(host), ".") {
		return ""
	}
	return c
}

// cymruOriginName builds the Team Cymru IP-to-ASN query name for an IPv4 or IPv6 address.
func cymruOriginName(ip net.IP) string {
	if v4 := ip.To4(); v4 != nil {
		return fmt.Sprintf("%d.%d.%d.%d.origin.asn.cymru.com", v4[3], v4[2], v4[1], v4[0])
	}
	v6 := ip.To16()
	if v6 == nil {
		return ""
	}
	const hexDigits = "0123456789abcdef"
	var b strings.Builder
	for i := len(v6) - 1; i >= 0; i-- {
		b.WriteByte(hexDigits[v6[i]&0x0f])
		b.WriteByte('.')
		b.WriteByte(hexDigits[v6[i]>>4])
		b.WriteByte('.')
	}
	b.WriteString("origin6.asn.cymru.com")
	return b.String()
}

func splitPipe(s string) []string {
	f := strings.Split(s, "|")
	for i := range f {
		f[i] = strings.TrimSpace(f[i])
	}
	return f
}

// lookupASN returns the AS number, AS name and registry country for a public IP address.
func lookupASN(lookup txtLookup, ipStr string) (asn, name, country string) {
	ip := net.ParseIP(ipStr)
	if ip == nil || ip.IsLoopback() || ip.IsPrivate() || ip.IsUnspecified() {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// Example answer: "13335 | 104.16.0.0/13 | US | arin | 2014-03-28"
	txt, err := lookup(ctx, cymruOriginName(ip))
	if err != nil || len(txt) == 0 {
		return
	}
	f := splitPipe(txt[0])
	if len(f) < 3 || len(strings.Fields(f[0])) == 0 {
		return
	}
	asn = strings.Fields(f[0])[0]
	country = f[2]

	// Example answer: "13335 | US | arin | 2010-07-14 | CLOUDFLARENET, US"
	txt, err = lookup(ctx, "AS"+asn+".asn.cymru.com")
	if err == nil && len(txt) > 0 {
		if g := splitPipe(txt[0]); len(g) >= 5 {
			name = g[4]
		}
	}
	return
}

// ---------- CDN detection ----------

var cnameSuffixes = []struct{ suffix, cdn string }{
	{".cdn.cloudflare.net", "Cloudflare"},
	{".edgekey.net", "Akamai"},
	{".edgesuite.net", "Akamai"},
	{".akamaiedge.net", "Akamai"},
	{".akamai.net", "Akamai"},
	{".akamaized.net", "Akamai"},
	{".azurefd.net", "Azure Front Door"},
	{".azureedge.net", "Azure Front Door"},
	{".t-msedge.net", "Azure Front Door"},
	{".cloudfront.net", "Amazon CloudFront"},
	{".fastly.net", "Fastly"},
	{".fastlylb.net", "Fastly"},
	{".incapdns.net", "Imperva"},
}

// Networks of large cloud and CDN providers, matched against the AS name of the IP.
var asProviders = []struct{ marker, name string }{
	{"CLOUDFLARENET", "Cloudflare"},
	{"FASTLY", "Fastly"},
	{"AKAMAI", "Akamai"},
	{"INCAPSULA", "Imperva"},
	{"AMAZON", "Amazon"},
	{"MICROSOFT", "Microsoft"},
	{"GOOGLE", "Google Cloud"},
}

// headerCDN looks for CDN markers in the response headers.
func headerCDN(h http.Header) (cdn, evidence string) {
	server := strings.ToLower(h.Get("Server"))
	has := func(k string) bool { return h.Get(k) != "" }
	switch {
	case has("Cf-Ray"):
		return "Cloudflare", "header cf-ray"
	case server == "cloudflare":
		return "Cloudflare", "header server: cloudflare"
	case has("X-Azure-Ref"):
		return "Azure Front Door", "header x-azure-ref"
	case has("X-Amz-Cf-Id"), has("X-Amz-Cf-Pop"):
		return "Amazon CloudFront", "header x-amz-cf-id"
	case strings.HasPrefix(server, "akamaighost"), strings.HasPrefix(server, "akamainetstorage"):
		return "Akamai", "header server: " + server
	case has("Akamai-Grn"), has("Akamai-Cache-Status"), has("X-Akamai-Transformed"):
		return "Akamai", "header akamai-*"
	case has("X-Fastly-Request-Id"), strings.HasPrefix(h.Get("X-Served-By"), "cache-"):
		return "Fastly", "header x-served-by / x-fastly-request-id"
	case has("X-Iinfo"), strings.Contains(strings.ToLower(h.Get("X-Cdn")), "imperva"),
		strings.Contains(strings.ToLower(h.Get("X-Cdn")), "incapsula"):
		return "Imperva", "header x-iinfo / x-cdn"
	}
	return "", ""
}

func cnameCDN(cname string) (cdn, evidence string) {
	for _, c := range cnameSuffixes {
		if strings.HasSuffix(cname, c.suffix) {
			return c.cdn, "cname *" + c.suffix
		}
	}
	return "", ""
}

func asProvider(asName string) string {
	upper := strings.ToUpper(asName)
	for _, p := range asProviders {
		if strings.Contains(upper, p.marker) {
			return p.name
		}
	}
	return ""
}

// detectCDN names the cloud or CDN provider that accepts the TLS connection, with the evidence used.
//
// The owner of the IP address decides: that is where the TLS handshake actually ends.
// CDN headers from an IP in another network only show a CDN further behind (an upstream hop),
// so they do not count. Headers alone are used only when the IP owner is unknown.
// It returns an empty provider when the connection ends in a network that is not a known cloud or CDN.
func detectCDN(h http.Header, cname, asName string) (cdn, evidence string) {
	hdr, hdrEv := headerCDN(h)
	cn, cnEv := cnameCDN(cname)

	if p := asProvider(asName); p != "" {
		switch {
		case p == "Amazon" && (hdr == "Amazon CloudFront" || cn == "Amazon CloudFront"):
			p = "Amazon CloudFront"
		case p == "Amazon":
			p = "Amazon AWS"
		case p == "Microsoft" && (hdr == "Azure Front Door" || cn == "Azure Front Door"):
			p = "Azure Front Door"
		case p == "Microsoft":
			p = "Microsoft Azure"
		}
		return p, "IP owner " + asName
	}
	if cn != "" {
		if asName != "" {
			return cn, cnEv + ", edge node in " + asName
		}
		return cn, cnEv
	}
	if asName != "" {
		if hdr != "" {
			return "", hdrEv + " seen, but the IP is not " + hdr + "'s: " + hdr + " is only further behind"
		}
		return "", ""
	}
	return hdr, hdrEv // IP owner unknown: fall back to headers
}

// ---------- one site ----------

func check(s Site) Result {
	host, port := splitHostPort(s.Host)
	r := Result{Site: s}

	classic := []tls.CurveID{tls.X25519, tls.CurveP256, tls.CurveP384}
	st, ip, err := handshake(host, net.JoinHostPort(host, port), classic, tls.VersionTLS10)
	if err != nil {
		r.Error = err.Error()
		return r
	}
	r.Reachable = true
	r.TLSVersion = versionName(st.Version)
	r.IP = ip
	if len(st.PeerCertificates) > 0 {
		r.CertIssuer = issuerName(st.PeerCertificates[0])
	}

	// Same IP for every following request, so all answers come from the same server or CDN node.
	target := net.JoinHostPort(ip, port)
	pq := []tls.CurveID{tls.X25519MLKEM768}
	for attempt := 0; attempt < 2; attempt++ {
		if _, _, err = handshake(host, target, pq, tls.VersionTLS13); err == nil {
			r.PQ = true
			r.Error = ""
			break
		}
		r.Error = err.Error()
		time.Sleep(time.Second)
	}

	headers := fetchHeaders(host, ip, port)
	r.Server = headers.Get("Server")
	r.CNAME = lookupCNAME(host)
	r.ASN, r.ASName, r.IPCountry = lookupASN(lookupTXT, ip)
	r.CDN, r.Evidence = detectCDN(headers, r.CNAME, r.ASName)
	return r
}

func issuerName(c *x509.Certificate) string {
	org, cn := "", c.Issuer.CommonName
	if len(c.Issuer.Organization) > 0 {
		org = c.Issuer.Organization[0]
	}
	switch {
	case org != "" && cn != "" && org != cn:
		return org + " / " + cn
	case cn != "":
		return cn
	default:
		return org
	}
}

// commonIssuer returns the most frequent certificate issuer among reachable sites.
func commonIssuer(results []Result) (issuer string, count, reachable int) {
	freq := map[string]int{}
	for _, r := range results {
		if !r.Reachable || r.CertIssuer == "" {
			continue
		}
		reachable++
		freq[r.CertIssuer]++
		if freq[r.CertIssuer] > count {
			count, issuer = freq[r.CertIssuer], r.CertIssuer
		}
	}
	return
}

// inspectionSuspected: real sites use many different certificate authorities.
// When most of them show the same issuer, a firewall is re-signing the traffic.
func inspectionSuspected(count, reachable int) bool {
	return reachable >= 5 && count*10 >= reachable*7
}

func status(r Result) string {
	switch {
	case !r.Reachable:
		return "unreachable"
	case r.PQ:
		return "yes"
	case r.TLSVersion != "TLS 1.3":
		return fmt.Sprintf("no (%s, no TLS 1.3)", r.TLSVersion)
	default:
		return "no"
	}
}

func provider(r Result) string {
	switch {
	case r.CDN != "":
		return r.CDN + " (cloud/CDN)"
	case r.ASName != "":
		return r.ASName
	default:
		return "-"
	}
}

func dash(s string) string {
	if s == "" {
		return "-"
	}
	return s
}

func truncate(s string, n int) string {
	rs := []rune(s)
	if len(rs) <= n {
		return s
	}
	return string(rs[:n-1]) + "…"
}

// ---------- output ----------

func writeCSV(path string, results []Result, checkedAt, network string) error {
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()
	f.WriteString("\xef\xbb\xbf") // BOM so Excel shows æ, ø, å correctly
	w := csv.NewWriter(f)
	w.Write([]string{"group", "organization", "host", "post_quantum", "tls", "cdn", "cdn_evidence",
		"ip", "asn", "as_name", "ip_country", "cname", "server_header", "cert_issuer", "error",
		"checked_at", "network", "tool_version"})
	for _, r := range results {
		asn := ""
		if r.ASN != "" {
			asn = "AS" + r.ASN
		}
		w.Write([]string{r.Group, r.Org, r.Host, status(r), dash(r.TLSVersion), r.CDN, r.Evidence,
			r.IP, asn, r.ASName, r.IPCountry, r.CNAME, dash(r.Server), r.CertIssuer, r.Error,
			checkedAt, network, version})
	}
	w.Flush()
	return w.Error()
}

func printTable(results []Result) {
	tw := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(tw, "GROUP\tORGANIZATION\tHOST\tPOST-QUANTUM\tTLS\tPROVIDER")
	for _, r := range results {
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\t%s\n", r.Group, truncate(r.Org, 28), r.Host, status(r),
			dash(r.TLSVersion), truncate(provider(r), 32))
	}
	tw.Flush()
}

func printSummary(results []Result) {
	type counts struct{ sites, reachable, pq, pqCDN int }
	var order []string
	byGroup := map[string]*counts{}
	for _, r := range results {
		if r.Group == "Control" {
			continue
		}
		c, ok := byGroup[r.Group]
		if !ok {
			c = &counts{}
			byGroup[r.Group] = c
			order = append(order, r.Group)
		}
		c.sites++
		if r.Reachable {
			c.reachable++
		}
		if r.PQ {
			c.pq++
			if r.CDN != "" {
				c.pqCDN++
			}
		}
	}
	tw := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(tw, "GROUP\tREACHABLE\tPOST-QUANTUM\tVIA CLOUD/CDN\tOTHER NETWORK")
	var total counts
	for _, g := range order {
		c := byGroup[g]
		fmt.Fprintf(tw, "%s\t%d\t%d\t%d\t%d\n", g, c.reachable, c.pq, c.pqCDN, c.pq-c.pqCDN)
		total.sites += c.sites
		total.reachable += c.reachable
		total.pq += c.pq
		total.pqCDN += c.pqCDN
	}
	fmt.Fprintf(tw, "TOTAL\t%d\t%d\t%d\t%d\n", total.reachable, total.pq, total.pqCDN, total.pq-total.pqCDN)
	tw.Flush()
	if total.reachable > 0 {
		fmt.Printf("\nReachable sites: %d of %d. With post-quantum key exchange: %d (%.0f%%)\n",
			total.reachable, total.sites, total.pq, 100*float64(total.pq)/float64(total.reachable))
	}
}

// cleanLabel turns user input into a short file-name-safe label; empty input means home.
func cleanLabel(s string) string {
	in := strings.ToLower(strings.TrimSpace(s))
	var b strings.Builder
	for _, r := range in {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9', r == '-':
			b.WriteRune(r)
		case r == ' ' || r == '_':
			b.WriteRune('-')
		}
	}
	switch {
	case in == "":
		return "home"
	case b.Len() == 0:
		return "other" // only characters that cannot go into a file name
	}
	return b.String()
}

func main() {
	network := flag.String("network", "", "label for where the check runs, e.g. home or school (asked if not given)")
	noWait := flag.Bool("nowait", false, "do not ask questions and do not wait for Enter before exiting")
	flag.Parse()
	stdin := bufio.NewReader(os.Stdin)
	if !*noWait {
		defer func() {
			fmt.Print("\nPress Enter to close...")
			stdin.ReadString('\n')
		}()
	}

	fmt.Printf("pqcheck %s - post-quantum TLS check (X25519MLKEM768) with cloud/CDN provider detection\n\n", version)
	if *network == "" && !*noWait {
		fmt.Print("Where are you measuring from? Type a short label, e.g. school, or just press Enter for home: ")
		line, _ := stdin.ReadString('\n')
		*network = line
	}
	*network = cleanLabel(*network)

	dir := "."
	if exe, err := os.Executable(); err == nil {
		dir = filepath.Dir(exe)
	}

	sites, source, err := loadSites(filepath.Join(dir, "sites.txt"))
	if err != nil {
		fmt.Println("Error:", err)
		return
	}
	fmt.Printf("\nChecking %d sites from %s (network: %s). This takes about a minute...\n\n", len(sites), source, *network)

	results := make([]Result, len(sites))
	sem := make(chan struct{}, 8)
	var wg sync.WaitGroup
	for i, s := range sites {
		wg.Add(1)
		go func(i int, s Site) {
			defer wg.Done()
			sem <- struct{}{}
			results[i] = check(s)
			<-sem
		}(i, s)
	}
	wg.Wait()
	checkedAt := time.Now().Format("2006-01-02 15:04")

	printTable(results)
	fmt.Println()
	printSummary(results)
	fmt.Printf("Checked at %s, network: %s\n", checkedAt, *network)

	if issuer, count, reachable := commonIssuer(results); reachable > 0 {
		fmt.Printf("Most common certificate issuer: %s (%d of %d sites)\n", issuer, count, reachable)
		if inspectionSuspected(count, reachable) {
			fmt.Printf("\nWARNING: %d of %d sites have certificates from the same issuer.\n", count, reachable)
			fmt.Println("This network probably inspects HTTPS traffic (TLS inspection): the results describe")
			fmt.Println("the firewall, not the websites. Do not use this run.")
		}
	}

	for _, r := range results {
		if r.Group == "Control" && !r.PQ {
			fmt.Println("\nWARNING: the control site did not negotiate X25519MLKEM768 - results of this run are unreliable.")
			fmt.Println("An antivirus or firewall that inspects HTTPS traffic can cause this.")
			break
		}
	}

	csvPath := filepath.Join(dir, fmt.Sprintf("pq_survey_%s_%s.csv", checkedAt[:10], *network))
	if err := writeCSV(csvPath, results, checkedAt, *network); err != nil {
		fmt.Println("\nCould not save CSV:", err)
		return
	}
	fmt.Println("\nSaved:", csvPath)
}
