# adguard-blockpage

The page CSPB's AdGuard Home shows when someone opens a blocked site. It tells
the user **which site** was blocked, the **block type** (blocklist, blocked
service, safe browsing, parental control) and the **category** (gambling, adult
content, phishing, a named service, a custom school rule, and so on).

Styling follows the cspb-sis design system (`cspb-sis/DESIGN.md`): moss, gold
and cream, DM Sans body, Playfair Display headings.

| Desktop | Phone |
|---|---|
| ![Desktop](docs/screenshot-desktop.png) | ![Phone](docs/screenshot-phone.png) |

## How it works

1. AdGuard answers a blocked DNS query with this server's IP instead of `0.0.0.0`
   (`blocking_mode: custom_ip`).
2. The browser connects to this server but still asks for the blocked site, so
   the `Host` header and `location.href` name the site the user tried to open.
3. `server.py` returns `public/index.html` for every path on every host.
4. The page calls `/__blockpage/info`. The server asks AdGuard's
   `GET /control/filtering/check_host?name=<host>&client=<ip>` why that host is
   blocked for that device, maps the result to a block type and category, and
   returns JSON. AdGuard credentials stay on the server.

If the lookup fails, the page still shows the blocked site and says the details
are unavailable. If AdGuard no longer blocks the host, the page says so and tells
the user to reload in a minute.

### Categories

| AdGuard reason | Block type | Category shown |
|---|---|---|
| `FilteredBlackList`, list id 0 | Blocklist | Custom school rule |
| `FilteredBlackList` | Blocklist | From the filter list name (table below), or the list name itself |
| `FilteredBlockedService` | Blocked service | The service name, e.g. Tinder |
| `FilteredSafeBrowsing` | Safe browsing | Malware or phishing |
| `FilteredParental` | Parental control | Adult content |
| `FilteredSafeSearch` | Safe search | Safe search enforced |

Filter list name keywords, first match wins: porn/adult → Adult content,
phish → Phishing, scam → Scam, gambling → Gambling, piracy → Piracy,
dating → Dating, vpn/proxy/bypass/tor → VPN and proxy bypass, dyndns → Dynamic
DNS, nocoin/coin → Cryptojacking, malware/urlhaus/badware/threat/hacked →
Malware and security threats, AdGuard DNS filter/adaway/ads → Ads and trackers.
Edit `LIST_CATEGORIES` in `server.py` when a new list is added.

## Limitation: HTTPS

The page only appears for **plain HTTP** requests. For `https://` sites the
browser expects a certificate for the blocked domain, which this server cannot
present, so the user sees a certificate or connection error instead. Sites on the
HSTS preload list (most large sites) never fall back to HTTP. This is how every
DNS-based block page works; showing the page for HTTPS needs a TLS-intercepting
proxy with a school CA installed on every device.

## Configuration

| Variable | Default | Meaning |
|---|---|---|
| `ADGUARD_URL` | `http://127.0.0.1:3000` | AdGuard Home web/API address |
| `ADGUARD_USER` | | AdGuard user for `check_host` (Basic auth) |
| `ADGUARD_PASSWORD` / `ADGUARD_PASSWORD_FILE` | | Its password, never logged |
| `BLOCKPAGE_LISTEN` | `0.0.0.0:8080` | Bind address |
| `BLOCKPAGE_TRUST_PROXY` | `0` | `1` to read the client IP from `X-Forwarded-For` |
| `BLOCKPAGE_PROXY_IPS` | `127.0.0.1,::1` | Proxy IPs or CIDRs allowed to set it; only the rightmost entry is used |

AdGuard has no read-only role, so the block page uses its own AdGuard user
rather than the admin account. The info endpoint only looks up the request's own
`Host` and rejects anything that is not a hostname.

Blocked ads, scripts and images also arrive here. Requests whose
`Sec-Fetch-Dest` is not a document or frame get a one-line plain-text 403 with no
AdGuard lookup, so tracker traffic stays cheap.

## Deploy (prod)

CI builds `ghcr.io/cspb1913/adguard-blockpage:sha-<commit>` and `:latest` on every
push to `main` after the tests pass, and smoke-tests the pushed image.

Prod runs in the on-prem cluster through the `tf-gke` GitOps repo
(`charts/school`, `blockpage:` in `values-onprem-cspb.yaml`). A merge to tf-gke
`master` deploys it. Releasing a new image means bumping the tag there.

```
LAN client ── DNS ──▶ AdGuard (10.116.192.41)  blocked → 10.116.192.245
LAN client ── HTTP ─▶ ingress-nginx VIP 10.116.192.245 ── no matching host ──▶ blockpage
blockpage ── check_host ──▶ AdGuard API (10.116.192.41:3000)
```

- One replica, 1m CPU request. The host-less Ingress makes the block page
  ingress-nginx's default server, so it receives every request whose host has no
  Ingress of its own. It only accepts LAN source ranges.
- Requests that arrive through Cloudflare (they carry `CF-Ray`, `CF-Connecting-IP`
  or `CDN-Loop: cloudflare`, which clients cannot strip) get a plain 404 and no
  AdGuard lookup. The cluster trusts forwarded headers, so a public tunnel
  hostname with no Ingress could otherwise reach this default server and forge
  its way past the LAN allowlist.
- HTTPS requests to blocked sites reach ingress-nginx's default certificate and
  fail at once, as described above.
- Credentials live in the Secret `adguard-blockpage` (keys `username`,
  `password`), created out of band in namespace `cspb`.

AdGuard settings (`AdGuardHome.yaml`, edited with AdGuard stopped):

```yaml
dns:
  blocking_mode: custom_ip
  blocking_ipv4: 10.116.192.245
  blocking_ipv6: "::"
```

Check it from a LAN client:

```bash
dig @10.116.192.41 <blocked domain> +short    # → 10.116.192.245
curl -s -H 'Host: <blocked domain>' http://10.116.192.245/__blockpage/info
```

Clients cache DNS answers, so a device may take a few minutes to see a change.
To roll back, set `blocking_mode: default` again.

## Development

```bash
python3 -m unittest discover -s tests -v
ADGUARD_USER=... ADGUARD_PASSWORD=... BLOCKPAGE_LISTEN=127.0.0.1:8080 python3 server.py
curl -s -H 'Host: tinder.com' http://127.0.0.1:8080/__blockpage/info
```

To preview a blocked host in Chrome without changing DNS:
`google-chrome --host-resolver-rules="MAP * 127.0.0.1:8080, EXCLUDE fonts.googleapis.com, EXCLUDE fonts.gstatic.com" http://tinder.com/`.
