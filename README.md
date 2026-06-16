# InviteAccess

Restricts site access to visitors with a valid invite code. Designed for staging environments with multiple teams.

---

**Author:** Maxim Semenov  
**Website:** [smnv.org](https://smnv.org)  
**Email:** [maxim@smnv.org](mailto:maxim@smnv.org)

If this project helps your work, consider supporting future development: [GitHub Sponsors](https://github.com/sponsors/mxmsmnv) or [smnv.org/sponsor](https://smnv.org/sponsor/).  

## Features

- Multiple invite codes — one per line, with optional human-readable labels
- Session-based auth with signed cookie fallback — visitors enter the code once, stay in for a configurable duration
- Access log — JSON log with timestamp, IP, user agent, URL and code label for every attempt
- Light / Dark / Auto theme on the access page — preference saved in localStorage
- Superuser always bypasses — logged-in ProcessWire users are never blocked
- Allowed pages — specific pages can be made publicly accessible even while the site is locked
- Clean, minimal UI — ApfelGrotezk font, processwire.com-inspired design, Bootstrap Icons
- Accent color presets — red, blue, green or black, configurable per-install

---

## Installation

1. Download or clone the repository into your `site/modules/` directory:

```bash
cd site/modules
git clone https://github.com/mxmsmnv/InviteAccess.git
```

2. In the ProcessWire admin, go to **Modules → Refresh**, then find **InviteAccess** and click **Install**.

3. Configure the module under **Modules → Configure → InviteAccess**.

---

## Configuration

| Field | Description | Default |
|---|---|---|
| Enable Invite Access | Master on/off switch | off |
| Invite Codes | One code per line, optional `code\|Label` format | — |
| Access Page Title | Heading shown on the access gate page | `Access Required` |
| Message | Subtext shown below the heading | `Please enter your invite code to continue.` |
| Error Message | Shown when an invalid code is submitted | `Invalid invite code. Please try again.` |
| Button Label | Text on the submit button | `Continue` |
| Style | Accent color for button and input focus border: `red`, `blue`, `green`, `black` | `red` |
| Session Duration | Hours before the visitor must re-enter their code | `1` |
| Always Accessible Pages | Pages that bypass the invite check entirely | — |
| Enable access logging | Write all access attempts to a JSON file | on |
| Log file path | Custom path for the log file (optional) | `site/assets/logs/invite-access.json` |

---

## Invite Code Format

Codes are defined one per line in the **Invite Codes** field. You can optionally add a pipe-separated label that appears in the access log:

```
SUMMER2025|Summer Campaign
AGENCY-PREVIEW|Agency Team
CLIENT-ACCESS|Client Preview
# this line is a comment and will be ignored
PLAINCODE
```

Labels make it easy to identify which team or campaign each access attempt belongs to when reading the log.

---

## Access Log

When logging is enabled, every access attempt is written to a JSON file (newest first). Each entry contains:

```json
{
  "time": "2026-02-27 14:32:10",
  "timestamp": 1772179930,
  "success": true,
  "code": "AGENCY-PREVIEW",
  "code_label": "Agency Team",
  "ip": "93.184.216.34",
  "ua": "Mozilla/5.0 ...",
  "url": "/about/"
}
```

Failed attempts log `"success": false` and redact the submitted value to `(invalid: ...)`. The log is capped at 1000 entries. The last 50 entries are also displayed directly in the module's admin config page.

---

## How It Works

The module hooks into `ProcessPageView::execute` — the earliest point in ProcessWire's request lifecycle — before any template or page rendering occurs. This ensures the gate fires reliably on all frontend URLs without interfering with the admin panel.

On a valid code submission, the module stores the code and an expiry timestamp in the ProcessWire session and in a signed HTTP-only fallback cookie. The fallback keeps access working on sites that disable guest sessions with `$config->sessionAllow`. Subsequent requests validate that stored code without touching the database. If a code is removed from the config, any active session or fallback cookie using that code is immediately invalidated.

---

## Security Notes

- Codes are compared using `hash_equals()` to prevent timing attacks
- Fallback access cookies are signed with HMAC and marked HTTP-only
- CSRF token is included in the access form
- IP detection respects Cloudflare (`CF-Connecting-IP`) and proxy headers (`X-Forwarded-For`)
- The module is intended for staging environments, not as a substitute for HTTP authentication on sensitive production data

---

## Author

**Maxim Semenov**
[smnv.org](https://smnv.org) · [GitHub @mxmsmnv](https://github.com/mxmsmnv)

---

## License

MIT License. See [LICENSE](LICENSE) for details.
