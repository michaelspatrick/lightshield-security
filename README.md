# LightShield Security (WordPress)
_A fast, lightweight shield for WordPress that plays nicely with Cloudflare._

**Current version:** 1.4.2
**License:** GPLv2 or later

LightShield focuses on the highest-impact protections with a clean UI:

- Brute-force login protection
- Bad/empty User-Agent blocking
- XML-RPC blocking
- 404/probe throttling
- Simple request rate limiting (optional)
- Malicious pattern filter (URI & query)
- IP allow/deny lists with **edge push to Cloudflare** (optional)
- Security headers & cookie hardening
- **Activity Log** (ring buffer) + **Dashboard** (charts)
- “Null IP” & internal task (cron/WP-CLI) safety guards

No custom tables. Minimal overhead. Works great in front of or behind Cloudflare.

---

## Table of Contents
- [Requirements](#requirements)
- [Installation](#installation)
- [Quick Start](#quick-start)
- [Admin Screens](#admin-screens)
  - [Blocked IPs](#blocked-ips)
  - [Settings](#settings)
  - [Log](#log)
  - [Dashboard (charts)](#dashboard-charts)
- [Cloudflare Integration (optional)](#cloudflare-integration-optional)
- [How LightShield Blocks/Denies](#how-lightshield-blocksdenies)
- [All Settings Explained](#all-settings-explained)
  - [Core](#core)
  - [Whitelist](#whitelist)
  - [404 / Probe Blocker](#404--probe-blocker)
  - [Malicious Pattern Filter](#malicious-pattern-filter)
  - [REST API](#rest-api)
  - [Headers & Cookies](#headers--cookies)
  - [Cloudflare](#cloudflare)
- [Activity Log & Event Types](#activity-log--event-types)
- [Dashboard Metrics](#dashboard-metrics)
- [Testing & Verification](#testing--verification)
- [Cron, WP-CLI, and Localhost](#cron-wp-cli-and-localhost)
- [Timezones](#timezones)
- [Performance & Storage](#performance--storage)
- [Security Notes](#security-notes)
- [Troubleshooting](#troubleshooting)
- [Changelog](#changelog)

---

## Requirements
- **WordPress:** 6.0+ (single or multisite; network activate if desired)
- **PHP:** 7.4+ (tested up to PHP 8.3)
- Optional: **Cloudflare** (for edge IP blocking)

---

## Installation
1. Download the release ZIP or clone into `wp-content/plugins/lightshield-security/`.
2. Activate **LightShield Security** in **Plugins**.
3. Go to **LightShield → Settings** and set your preferences.

**Optional Dashboard file**  
If your version ships with a separate dashboard file, put `lightshield-dashboard.php` next to `lightshield-security.php`.  
The main plugin auto-loads it when present (or add this one line near the bottom of the main file):

```php
if (is_admin() && file_exists(__DIR__ . '/lightshield-dashboard.php')) {
    require_once __DIR__ . '/lightshield-dashboard.php';
}
```

---

## Quick Start
- Turn on **Disable XML-RPC**.
- Keep **Bad/Empty User-Agent block** enabled.
- Set **Login failures** to e.g. `5` and **Block duration** to `15` minutes.
- (Optional) Enable **404 / Probe Blocker** with a threshold like `12` in `5` minutes.
- (Optional) Add your own **Malicious patterns** to match your site.
- (Optional) Enable **Cloudflare** and provide Zone ID + API Token.
- Check **Log** to verify activity, then explore the **Dashboard**.

---

## Admin Screens

### Blocked IPs
- Table of active blocks with **Reason**, **Blocked at**, **Expires**, and **Edge (CF)** indicator.
- **Unblock** button clears the local block (and removes the Cloudflare Access Rule if enabled).
- **Manually Block an IP** form (enter IP + minutes).

### Settings
All configuration lives here. See [All Settings Explained](#all-settings-explained).

### Log
- Rolling list of recent events (latest first).  
- **Clear Log** button wipes entries.
- Capped at **1,000 entries** (ring buffer) to avoid bloat.
- Timestamps use your **site timezone**.

### Dashboard (charts)
- **Summary cards**: Denied Requests, Blocks Created, Unique IPs Touched, Cloudflare Edge Blocks.
- Charts:
  - Line: **Denied requests per day**
  - Bar: **Blocks created per day**
  - Doughnut: **Top reasons** (from log)
- **Top lists**: IPs, denied URIs, denied User-Agents.
- Range selector: last 7–180 days.

> If you enforce a strict CSP, allow the Chart.js CDN or host it locally.

---

## Cloudflare Integration (optional)
LightShield can push IP blocks to Cloudflare **IP Access Rules** so traffic is stopped at the edge.

**Enable**: In **Settings → Cloudflare**  
- Check **Edge Blocking**  
- Enter **Zone ID** and **API Token**, then **Save**  
- Use **Test Cloudflare API** to verify connectivity  
- **Sync & Clean** removes stale *LightShield-created* rules in your zone

**API Token permissions (zone-scoped):**
- **Zone: Read**
- **Zone: Firewall Services: Edit**

> Tip: In Cloudflare WAF, add a rule `cf.client.bot` → **Skip** (WAF/Rate Limiting) to allow verified crawlers while still blocking attackers. If you use Bot Fight Mode and see issues, switch to Super Bot Fight Mode or disable BFM for your zone.

---

## How LightShield Blocks/Denies
- **Denies (403)** happen immediately in PHP when a rule triggers (e.g., XML-RPC disabled, malicious pattern, rate limit exceeded, too many 404s, existing block).
- **Blocks** are recorded in the **local blocklist** (with expiry). If Cloudflare is enabled, an **IP Access Rule** is created for that IP.  
- **Auto-unblock**: expired blocks are pruned automatically (hourly scheduler + lightweight “tick” on request). Unblocking in the UI removes the CF rule too.

**Safety guards**
- **Null IP**: If client IP resolves to `0.0.0.0` or `::`, LightShield **never blocks** and skips protections (logs one debounced `ip_resolve_fail`).
- **Internal tasks**: Requests recognized as **wp-cron**, **WP-CLI**, or localhost loopbacks are skipped entirely (no logs, no blocks).

---

## All Settings Explained

### Core
- **Trust Cloudflare Headers**  
  Uses `CF-Connecting-IP` / `X-Forwarded-For` to get the real client IP when proxied by Cloudflare.  
  _Recommended when your DNS is “orange-clouded”._

- **Disable XML-RPC**  
  Blocks all `xmlrpc.php` requests (unless IP is whitelisted).  
  This closes a common brute-force vector.

- **Block Bad/Empty User-Agents**  
  Immediate block (default 60 min) for clearly abusive UAs or empty UA strings.  
  Built-in “good UA” substrings (e.g., major crawlers) are allowed.

- **Global Throttle (optional)**  
  Throttles all unauthenticated requests per IP to **N per minute**. Exceeding the limit adds a temporary block.

- **Login Brute-Force Limit**  
  Count failed logins per IP. When the count reaches **Failed attempts**, the IP is blocked for **Block duration** minutes.

### Whitelist
- One IP per line.  
- Whitelisted IPs bypass everything (XML-RPC block, throttle, etc.).  
- Use this for your static office IPs or monitoring nodes.

### 404 / Probe Blocker
- **Enable** to count 404s per IP.  
- Block when **Threshold** 404s occur within **Window (minutes)**.  
- **Block duration** controls how long the block remains.

### Malicious Pattern Filter
- Matches substrings (case-insensitive) across URI + query.  
- Defaults include: `../`, `.env`, `wp-config`, `/.git`, `id_rsa`, `php://`, `expect://`, `base64_decode`, `union select`, `information_schema`, `/etc/passwd`, and more.  
- Add your own one per line. Lines starting with `#` are ignored.  
- On match: **immediate deny** and block for **Block duration** minutes.

### REST API
- **Require Authentication**  
  Denies anonymous REST requests **unless** they match your **Allowlist**.  
- **Allowlist (regex per line)**  
  PCRE patterns matched against the request path (e.g., `^/oembed/1\.0`, `^/wp-site-health`, `^/wp/v2/types`, `^/wp/v2/taxonomies`).  
  Use this to permit specific endpoints that public features need.

### Headers & Cookies
- **Enable** to add common security headers and harden cookies:
  - **X-Frame-Options:** `SAMEORIGIN`
  - **X-Content-Type-Options:** `nosniff`
  - **Referrer-Policy:** default `strict-origin-when-cross-origin` (editable)
  - **CSP (Report-Only):** send a `Content-Security-Policy-Report-Only` header with your policy value (default: `default-src 'self' data: blob:; frame-ancestors 'self';`)
  - **Cookie Hardening:** forces `Secure`/`HttpOnly` (when SSL) and `SameSite=Lax` on session cookies
- **Disable File Editor** hides the built-in theme/plugin editors in wp-admin.

> Start CSP in **Report-Only** until you’re confident no assets are blocked. If you enforce CSP, include any CDNs you actually use (e.g., for the Dashboard’s Chart.js or your theme assets).

### Cloudflare
- **Edge Blocking** toggles API usage.  
- **Zone ID** identifies the site’s zone.  
- **API Token** (stored securely) with **Zone:Read** and **Zone: Firewall Services:Edit**.  
- **Test Cloudflare API** tries a create/delete cycle to confirm permissions.  
- **Sync & Clean** removes stale **LightShield-created** rules from your zone (useful if blocks were removed locally or expired).

---

## Activity Log & Event Types
The log keeps the last **1,000** events (ring buffer). Each entry includes timestamp, IP, action, reason, URI, User-Agent, and small metadata.

**Common actions**
- `block` — local block created
- `deny` — request denied (403) due to a rule
- `rest_deny` — REST API denied (requires auth)
- `auto_unblock` — expired block removed automatically
- `unblock` — manual unblock from UI
- `cf_block` / `cf_unblock` — Cloudflare rule created/removed
- `cf_cleanup` — stale LightShield rules removed at Cloudflare
- `cf_error` / `cf_test_ok` / `cf_test_fail` — Cloudflare API results
- `settings_saved` — settings changed
- `ip_resolve_fail` — client IP could not be determined (debounced)
- `skip_block` / `skip_login_fail` / `probe_skip` / `throttle_skip` / `rest_skip` — request ignored due to null IP or internal task
- `cleanup` — removed invalid IP from blocklist

Use **Log → Clear Log** to wipe the buffer.

---

## Dashboard Metrics
- **Denied Requests** — total number of 403s (including rule-based blocks, REST denials, etc.) in the range
- **Blocks Created** — number of new local blocks (includes IPs that were also pushed to Cloudflare)
- **Unique IPs Touched** — unique IPs that were denied or blocked
- **Cloudflare Edge Blocks** — count of successful edge push events
- **Charts** — trends per day for denies/blocks, top reasons by count
- **Top Lists** — IPs, URIs, and UAs most frequently involved in denials

---

## Testing & Verification
**Brute-force trip (unauthenticated):**
```bash
# 11 bad login attempts in a row
COOKIE=/tmp/ls_cookie
DOMAIN="https://example.com"
for i in {1..11}; do
  curl -s -L -c $COOKIE -b $COOKIE -o /dev/null     -d "log=admin&pwd=nottherightpass$i&wp-submit=Log+In&redirect_to=/wp-admin/&testcookie=1"     "$DOMAIN/wp-login.php"
done
```

**XML-RPC block:**
```bash
curl -i "https://example.com/xmlrpc.php"
# Expect: HTTP/1.1 403 ... "XML-RPC disabled."
```

**Probe/404 block:** hit non-existent paths rapidly to exceed your threshold/window.

**Cloudflare push:** Enable CF, then use **Manually Block an IP** or cause an automatic block. Check **Security → WAF → Tools → IP Access Rules** in Cloudflare.

---

## Cron, WP-CLI, and Localhost
LightShield intentionally **skips** all protections and logging for:
- WordPress cron (`DOING_CRON`), WP-CLI (`WP_CLI`), or PHP CLI processes
- Direct hits to `/wp-cron.php`
- Localhost loopbacks (`127.0.0.1` / `::1`) without Cloudflare headers
- Requests that include header `X-LS-Internal: 1`

This prevents false positives like `0.0.0.0` and keeps the log clean.

**Best practice:** disable pseudo-cron and run via WP-CLI:
```php
// wp-config.php
define('DISABLE_WP_CRON', true);
```
```bash
*/5 * * * * sudo -u apache wp cron event run --due-now --path=/path/to/wordpress --quiet
```

---

## Timezones
All times in the UI and log use your **site timezone** (Settings → General → Timezone).

---

## Performance & Storage
- No custom tables.  
- Uses WordPress **options/transients**.  
- Blocklist holds active entries only; auto-pruned.  
- Log is capped at **1,000** entries; clearing is one click.  
- Scheduler runs a light hourly prune, plus a lightweight safety tick.

---

## Security Notes
- This is not a full WAF. For best results, run behind **Cloudflare** and consider a WAF ruleset.
- Start CSP in **Report-Only**. When enforcing, include all domains you actually load assets from.
- If your site is proxied by Cloudflare, configure your web server to pass the real client IP to PHP (e.g., nginx `real_ip_header CF-Connecting-IP` with `set_real_ip_from` ranges, or Apache `mod_remoteip`). This minimizes `ip_resolve_fail`.

---

## Troubleshooting
- **“Cloudflare not enabled or missing Zone ID/token.”**  
  Ensure Edge Blocking is checked, Zone ID set, and a token with `Zone:Read` + `Zone: Firewall Services:Edit` is saved. Use **Test Cloudflare API**.

- **Blocks don’t expire in Cloudflare**  
  LightShield unblocks at CF when a local block expires or you manually unblock. If you removed local blocks outside the UI, use **Sync & Clean**.

- **Legit bots blocked (e.g., Applebot)**  
  Add a Cloudflare WAF Skip rule for `cf.client.bot`, or whitelist specific IPs/hostnames. You can also tweak UA allow-list in the plugin.

- **Log fills with `0.0.0.0`**  
  That generally means internal cron/localhost. LightShield skips these by default; if you still see events, verify your guards and real IP configuration.

- **Filesystem/FTP errors in cron**  
  In `wp-config.php`: `define('FS_METHOD','direct');` and run cron as the web user so WooCommerce and others can write logs.

---

## Changelog
**1.3.1**
- Safety: never block when client IP is `0.0.0.0` or `::`; early exit on null IPs
- Internal task detection (cron, WP-CLI, localhost) skips all logic & logging
- Minor UA allow-list improvement (major crawlers)

**1.3.0**
- New **Activity Log** (ring buffer, 1,000 entries) with **Clear Log** button
- Optional **Dashboard** with charts and top lists
- Cloudflare: sync cleanup and better error logging
- Uses site timezone for timestamps

**≤1.2.x**
- Core protections (login BF, XML-RPC, bad UA, probe/404, patterns, REST lock)
- Security headers & cookie hardening
- IP whitelist/blocklist UI
- Optional Cloudflare edge blocking

---

## Contributing
Issues and PRs welcome. Please:
- Keep changes small and focused
- Explain the threat model and performance impact
- Avoid heavy dependencies

---

## License
GPLv2 or later.

