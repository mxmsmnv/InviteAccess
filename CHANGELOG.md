# Changelog

All notable changes to InviteAccess are documented here.

---

## [Unreleased]

### Added
- Per-environment overrides: `$config->inviteAccess`, an array of module settings in a config file, overrides the saved configuration when the gate runs, so a development copy of a production database can keep the gate off. Overridden keys are named on the configuration screen without their values.

---

## [1.0.3] — 2026-09-10

### Fixed
- CLI bootstraps bypass the HTTP gate (fixes #3).
- Redirect targets are restricted to unambiguous local paths and query strings are removed.
- Admin and allowed-page exceptions match complete path segments; ambiguous traversal, encoded traversal, backslashes and repeated slashes do not qualify for exceptions.
- Invite submissions require a signed, expiring double-submit CSRF token. This replaces the previously unvalidated ProcessWire token and works with guest sessions disabled.
- Both admin log-path displays escape HTML.
- Log updates use a stable exclusive lock and atomic replacement; corrupt history is preserved rather than silently overwritten. Invalid UTF-8 input does not corrupt JSON.
- Access logs use `REMOTE_ADDR`, ignoring untrusted forwarded headers.
- Cookies cannot be signed or verified without `userAuthSalt`; predictable signing-key fallbacks are removed.
- Gate and redirect responses use `Cache-Control: no-store, private`.
- Numeric invite codes no longer cause a type error during comparison.

### Changed
- New installations start with no example invite codes. Existing configured codes are preserved.
- Cookie paths follow the ProcessWire installation root; Secure also respects ProcessWire's HTTPS configuration.
- Session duration is clamped to at least one hour.
- Allowed-page configuration warns that IDs must be reselected and verified when transferred between independent databases.

### Upgrade notes
- Reload any invite form opened before updating: the previous form token is no longer accepted.
- Configure a valid ProcessWire `userAuthSalt`. Guest-session-free access still works; no guest PHP session is required.
- Behind a reverse proxy, the log now records the connection address unless the web server securely resolves `REMOTE_ADDR` using a trusted-proxy configuration.
- Keep logs outside the public document root or deny HTTP access to their directory. Existing log entries and configured paths are not migrated or deleted.
- Allowed pages still include descendants, and the homepage does not exempt the whole site. Verify these exceptions after a configuration import; raw page IDs are not portable.
- Run `php tests/regression.php` and `python3 tests/http_regression.py` from the development repository. Do not deploy tests into a public document root.

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

*Maintained by [Maxim Semenov](https://smnv.org) · [github.com/mxmsmnv/InviteAccess](https://github.com/mxmsmnv/InviteAccess)*
