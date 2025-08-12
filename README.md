# LightShield Security (WordPress)

**Version:** 1.3.0
**Author:** Michael Patrick
**License:** GPLv2 or later

Lightweight protections for WordPress + optional **Cloudflare edge blocking**.

---

## Cloudflare edge blocking (optional)

When enabled, every IP that LightShield blocks is also pushed to **Cloudflare IP Access Rules** for your zone. When you **unblock** in LightShield, it attempts to delete the matching rule at Cloudflare.

### What you need
1. **Zone ID** for your domain.  
2. **API Token** with permission to edit IP Access Rules (Zone → Firewall Access Rules → Edit). Scope to your zone.

### Where to enable it
- WordPress Admin → **LightShield** → **Cloudflare Edge Blocking (optional)**.

### How it works
- Create: `POST /client/v4/zones/{zone_id}/firewall/access_rules/rules` with `{"mode":"block","configuration":{"target":"ip","value":"<IP>"}}`
- Delete: `DELETE /client/v4/zones/{zone_id}/firewall/access_rules/rules/{rule_id}`
- The plugin stores the returned `rule_id` mapped to the IP and removes it on unblock.

**New in 1.2.0**
- **404 / Probe blocker:** Blocks IPs that trigger many 404s in a short window (thresholds configurable).
- **Malicious pattern filter:** Instant block on obvious exploit strings in URL/query. Add your own patterns.
- **REST API lock:** Optional switch to require authentication for REST (with allowlist).
- **Headers & cookies:** X-Frame-Options, X-Content-Type-Options, Referrer-Policy, optional CSP (Report-Only), and cookie hardening.

---

## Install
1. Upload the ZIP via **Plugins → Add New → Upload** and activate.  
2. Open **LightShield** in admin to configure options and (optionally) Cloudflare.

---

## Changelog
### 1.1.1 — 2025-08-12
- Version bump and packaging fix; ensured Cloudflare integration is included.

### 1.1.0 — 2025-08-12
- Added optional **Cloudflare IP Access Rules** integration (edge blocking).

### 1.0.0 — 2025-08-12
- Initial release.

