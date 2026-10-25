# Post-quantum TLS survey of Norwegian public-sector websites

A small tool and dataset that check two things for the public websites of Norwegian state agencies:

1. Does the site accept **post-quantum key exchange** in TLS: the hybrid `X25519MLKEM768` group that current Chrome, Edge and Firefox use by default?
2. **Which network actually terminates the TLS connection**: the agency's own network, a Norwegian hosting provider, or a large cloud/CDN provider?

Why it matters: traffic recorded today can be decrypted later by a sufficiently large quantum computer ("store now, decrypt later") unless the key exchange is post-quantum. Key exchange is the part that protects recorded traffic. Post-quantum certificates and signatures are a separate, later step and are not measured here.

## Method

For every host in `sites.txt` the tool does the following:

1. **Classical handshake.** It makes a TLS handshake offering only classical groups (X25519, P-256, P-384) and records reachability, TLS version, the IP address that answered and the issuer of the server certificate.
2. **Post-quantum handshake.** It makes a TLS 1.3 handshake **to the same IP** offering only `X25519MLKEM768`. The host either accepts or refuses. One retry after one second.
3. **Response headers.** It sends one HTTPS `HEAD` request to the same IP, or `GET` if `HEAD` is refused, to read the response headers (`Server`, CDN markers such as `cf-ray`, `x-azure-ref`, `x-amz-cf-id`, `x-served-by`).
4. **DNS.** It looks up the CNAME of the host and the autonomous system (AS) that announces the IP, using the [Team Cymru IP-to-ASN DNS service](https://www.team-cymru.com/ip-asn-mapping).
5. **Provider classification.** **The owner of the IP address decides** which network terminates TLS. Known cloud/CDN networks are Cloudflare, Fastly, Akamai, Imperva, Amazon, Microsoft and Google. A CDN header coming from an IP in some other network only shows that a CDN sits further behind the server, so it does not count. A CNAME into a CDN (for example `*.edgesuite.net`) counts even when the edge node sits inside a local ISP.
6. **TLS inspection check.** Real websites use many different certificate authorities. If at least 70% of the reachable hosts present certificates from the same issuer, the network is probably re-signing HTTPS traffic (TLS inspection), and the run is flagged as invalid. The control host `pq.cloudflareresearch.com` must always show `yes`.

Certificates are not validated, because the tool measures key exchange only. Apart from the handshakes and one `HEAD`/`GET` request to the front page, nothing is sent.

## Limitations

- **Only the front-page host is measured.** Login services, APIs, e-mail and internal systems may run on other servers.
- **Network owner is not the same as server operator.** An IP announced by a Norwegian ISP can still be operated by the agency itself, or by a supplier.
- **Results depend on location and time.**
  - Some sites block cloud IP ranges: `www.norge.no` and `www.digdir.no` did not answer from Google Colab.
  - CDN and cloud nodes may behave differently. `www.ssb.no` (Google Cloud load balancer, same IP) accepted `X25519MLKEM768` on 19 Oct (from Google Colab), 23 Oct and 25 Oct 11:22 (both from home), but refused it on 25 Oct 12:19 (from home).
- **Antivirus software or firewalls that inspect HTTPS make the results describe the inspection device, not the website.** This is what the control host and the issuer check are for.
- **The sample covers the 21 national public-sector websites in `sites.txt`.** It is a spot check (stikkprøve), not an assessment of any agency's overall security.

## Data

`data/2026-10-25_home_state-sites.csv` comes from one run on 25 October 2026 at 12:19 from a residential internet connection in Norway, using pqcheck 1.3. It covers 21 national public-sector websites plus the control host.

Summary of that run:

| Group | Sites | Post-quantum key exchange | of them via cloud/CDN network | Terminating in a Norwegian network |
|---|---|---|---|---|
| Defence & security | 8 | 7 | 7 | 1 (no post-quantum) |
| Public services | 13 | 5 | 5 | 7 (no post-quantum) |

- **Every post-quantum answer came from a cloud/CDN network** (Fastly, Cloudflare, Microsoft).
- **None of the 8 sites that terminate TLS in a Norwegian network accepted `X25519MLKEM768`.**
- **`www.nav.no`, `www.stortinget.no` and `www.brreg.no` offered only TLS 1.2.** Post-quantum key exchange in TLS requires TLS 1.3.
- **`www.ssb.no` is the one cloud-hosted site without post-quantum key exchange in this run.** See the time dependence under Limitations.

### Columns

| Column | Meaning |
|---|---|
| `group`, `organization`, `host` | From `sites.txt` |
| `post_quantum` | `yes`, `no`, `no (TLS 1.2, no TLS 1.3)` or `unreachable` |
| `tls` | Highest TLS version negotiated in the classical handshake |
| `cdn` | Cloud/CDN network that terminates TLS; empty means another network |
| `cdn_evidence` | Why `cdn` was set, or why a CDN header was ignored |
| `ip`, `asn`, `as_name`, `ip_country` | Answering IP, its autonomous system and registry country |
| `cname` | Canonical name of the host, if different |
| `server_header` | `Server` response header |
| `cert_issuer` | Issuer organisation / common name of the server certificate |
| `error` | Handshake error from the post-quantum attempt, or connection error |
| `checked_at`, `network`, `tool_version` | When, from where (label given by the person running it) and with which version |

## Running it

**Windows.** Download `pqcheck.exe`, put it in a folder and double-click it. The program asks for a label for the network (press Enter for `home`). When it finishes, it saves `pq_survey_<date>_<label>.csv` next to the program. If `sites.txt` is missing, it is created with the default list. Windows SmartScreen warns about unsigned programs: choose *More info → Run anyway*.

**From source** (Go 1.24 or newer, which has `X25519MLKEM768` in `crypto/tls`):

```
go test ./...
go run . -network home
GOOS=windows GOARCH=amd64 go build -o pqcheck.exe .
```

Flags:

- `-network <label>`: label written to the CSV and the file name.
- `-nowait`: no questions and no "Press Enter" at the end (for scripts).

To check other sites, edit `sites.txt`. It takes one site per line, in the form `group | organization | host`. Keep the `Control` line.
