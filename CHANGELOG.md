# Changelog

All notable changes to InviteAccess are documented here.

---

## [1.0.2] — 2026-06-07

### Fixed
- Added a signed HTTP-only fallback cookie so valid invite access persists when ProcessWire guest sessions are disabled with `$config->sessionAllow`.
- Invalid invite-code errors now survive the post/redirect/get flow even when guest session storage is unavailable.

---

## [1.0.1] — 2026-02-27

Initial public release.

### Added
- `ProcessPageView::execute` hook for early frontend interception — fires before any template or page rendering
- Multiple invite codes with optional `code|Label` pipe syntax; comment lines (`#`) are ignored
- Session-based access with configurable expiry in hours (default: 1 hour)
- JSON access log with timestamp, IP, user agent, URL, code label and success/failure status; capped at 1000 entries
- Last 50 log entries displayed directly in the module admin config panel
- Superuser and all logged-in ProcessWire users bypass the gate automatically
- Admin URL always excluded from the gate
- Configurable allowed pages (bypass list) via `InputfieldPageListSelectMultiple`
- CSRF token included in the access form
- Cloudflare and proxy-aware IP detection (`CF-Connecting-IP`, `X-Forwarded-For`)
- `hash_equals()` used for timing-safe code comparison
- PRG redirect pattern after form submission (strips query string to prevent resubmit on F5)
- Demo invite codes pre-filled as defaults: `SUMMER2025`, `AGENCY-PREVIEW`, `CLIENT-ACCESS`
- **Button Label** config field — submit button text is fully customisable
- **Style** config field — accent color preset for button and input focus border: `red`, `blue`, `green`, `black`
- Access gate UI — ApfelGrotezk font, processwire.com-inspired layout (warm gray background, white card, mobile-first), Bootstrap Icons for theme switcher and button arrow
- `namespace ProcessWire` declaration added — required for ProcessWire 3.x compatibility

---

*Maintained by [Maxim Alex](https://smnv.org) · [github.com/mxmsmnv/InviteAccess](https://github.com/mxmsmnv/InviteAccess)*
