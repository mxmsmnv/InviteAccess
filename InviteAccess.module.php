<?php namespace ProcessWire;

/**
 * InviteAccess — ProcessWire Module
 *
 * Restricts frontend access to visitors who enter a valid invite code.
 * Useful for staging environments where multiple teams need separate access.
 *
 * Features:
 * - Multiple invite codes (one per line in config)
 * - Session-based auth with signed cookie fallback (enter once, remember until expiry)
 * - Access log (JSON) with date, IP, user agent, invite code used
 * - All logged-in ProcessWire users bypass the gate
 * - Configurable allowed pages (e.g. assets, API endpoints)
 * - Configurable allowed paths (e.g. webhooks that verify their own secrets)
 * - Per-environment overrides via $config->inviteAccess (e.g. gate off on a development copy)
 * - Optional per-code labels (e.g. "agency-team|Agency Design Team")
 *
 * @author Maxim Semenov <maxim@smnv.org> (smnv.org)
 * @license MIT
 */

class InviteAccess extends WireData implements Module, ConfigurableModule {

	/*
	 * ─────────────────────────────────────────────
	 * Module Info
	 * ─────────────────────────────────────────────
	 */
	public static function getModuleInfo() {
		return [
			'title'     => 'Invite Access',
			'summary'   => 'Restricts site access to visitors with a valid invite code. Designed for staging environments with multiple teams.',
			'version'   => 110,
			'autoload'  => true,
			'singular'  => true,
			'permanent' => false,
			'icon'      => 'key',
		];
	}

	/*
	 * ─────────────────────────────────────────────
	 * Default Config
	 * ─────────────────────────────────────────────
	 */
	public static function getDefaultData() {
		return [
			'enabled'        => 0,
			'inviteCodes'    => '',
			'pageTitle'      => 'Access Required',
			'pageMessage'    => 'Please enter your invite code to continue.',
			'errorMessage'   => 'Invalid invite code. Please try again.',
			'buttonLabel'    => 'Continue',
			'style'          => 'red',
			'sessionHours'   => 1,
			'logEnabled'     => 1,
			'logPath'        => '',
			'allowedPages'   => [],
			'allowedPaths'   => '',
			'logAllowedPaths' => 0,
		];
	}

	public function __construct() {
		foreach (self::getDefaultData() as $key => $value) {
			$this->$key = $value;
		}
	}

	/*
	 * ─────────────────────────────────────────────
	 * Init
	 * ─────────────────────────────────────────────
	 */
	public function init() {
		$this->addHookBefore('ProcessPageView::execute', $this, 'checkAccess');
	}

	/*
	 * ─────────────────────────────────────────────
	 * Access Check Hook
	 *
	 * NOTE: At ProcessPageView::execute stage, $this->wire('page') is NULL.
	 * We use $_SERVER['REQUEST_URI'] for URL-based decisions.
	 * ─────────────────────────────────────────────
	 */
	public function checkAccess(HookEvent $event) {
		// Command-line bootstraps are not HTTP requests.
		if (PHP_SAPI === 'cli' || $this->wire('config')->cli) return;
		// A config file may pin settings for this environment (see applyConfigOverrides).
		$this->applyConfigOverrides();
		if (!$this->enabled) return;

		$user = $this->wire('user');

		// Logged-in users always pass
		if ($user->isLoggedIn()) return;

		// Current request URL (before any PW routing)
		$requestUrl = (string) ($_SERVER['REQUEST_URI'] ?? '/');
		$requestPath = $this->normalizeRequestPath($requestUrl);
		$adminUrl = (string) $this->wire('config')->urls->admin;

		// Skip PW admin
		if ($this->pathMatches($requestPath, $adminUrl)) return;

		// Skip explicitly allowed pages
		if (!empty($this->allowedPages) && is_array($this->allowedPages)) {
			foreach ($this->allowedPages as $pid) {
				$pid = (int) $pid;
				if (!$pid) continue;
				$p = $this->wire('pages')->get($pid);
				if ($p && $p->id) {
					$pUrl = (string) $p->url;
					if ($this->pathMatches($requestPath, $pUrl)) return;
				}
			}
		}

		// Skip explicitly allowed paths (e.g. webhooks that verify their own secrets)
		$allowedPath = $this->matchAllowedPath($requestPath);
		if ($allowedPath !== null) {
			$this->logAllowedPath($allowedPath, $requestPath);
			return;
		}

		// Check existing valid session
		if ($this->hasValidSession()) return;

		// Handle form submission
		$postedCode = $this->wire('input')->post('invite_code');
		if (($_SERVER['REQUEST_METHOD'] ?? '') === 'POST' && is_string($postedCode) && $postedCode !== '') {
			$this->handleFormSubmit($postedCode, $requestUrl);
			// always exits inside
		}

		// Block — output form and halt
		$this->blockWithForm();
	}

	/*
	 * ─────────────────────────────────────────────
	 * Block execution and output the invite form
	 * ─────────────────────────────────────────────
	 */
	protected function blockWithForm() {
		// Clear any buffered output (PHP notices/warnings in dev mode)
		while (ob_get_level() > 0) {
			ob_end_clean();
		}

		if (!headers_sent()) {
			http_response_code(200);
			header('Content-Type: text/html; charset=utf-8');
			header('Cache-Control: no-store, private');
			header('Referrer-Policy: no-referrer');
		}

		echo $this->renderInviteForm();
		exit;
	}

	/*
	 * ─────────────────────────────────────────────
	 * Form Submit Handler
	 * ─────────────────────────────────────────────
	 */
	protected function handleFormSubmit($entered, $requestUrl) {
		$session = $this->wire('session');
		if (!$this->hasValidFormToken()) {
			$session->set('invite_access_error', 1);
			$this->blockWithForm();
			return;
		}
		$entered = trim($entered);
		$codes   = $this->parseCodes();

		foreach ($codes as $code => $label) {
			if (hash_equals((string) $code, $entered)) {
				$expires = time() + (max(1, (int) $this->sessionHours) * 3600);
				$session->set('invite_access_code',    $code);
				$session->set('invite_access_expires', $expires);
				$this->setAccessCookie($code, $expires);
				$this->clearErrorCookie();

				$this->writeLog($code, $label, true, $requestUrl);

				// PRG — redirect back to the same URL (minus query string)
				$redirectTo = $this->getRedirectPath($requestUrl);
				$this->redirect($redirectTo);
				exit;
			}
		}

		// Invalid
		$this->writeLog($entered, '', false, $requestUrl);
		$session->set('invite_access_error', 1);
		$this->setErrorCookie();

		$redirectTo = $this->getRedirectPath($requestUrl);
		$this->redirect($redirectTo);
		exit;
	}

	/*
	 * ─────────────────────────────────────────────
	 * Session Validation
	 * ─────────────────────────────────────────────
	 */
	protected function hasValidSession() {
		$session = $this->wire('session');
		$code    = (string) $session->get('invite_access_code');
		$expires = (int)    $session->get('invite_access_expires');

		if (!$code || !$expires) return $this->hasValidAccessCookie();

		if (time() > $expires) {
			$session->remove('invite_access_code');
			$session->remove('invite_access_expires');
			return $this->hasValidAccessCookie();
		}

		$codes = $this->parseCodes();
		if (isset($codes[$code])) return true;

		$session->remove('invite_access_code');
		$session->remove('invite_access_expires');
		return $this->hasValidAccessCookie();
	}

	protected function hasValidAccessCookie() {
		$cookie = $_COOKIE[$this->getAccessCookieName()] ?? '';
		if (!is_string($cookie) || $cookie === '') return false;

		$data = $this->decodeSignedCookie($cookie);
		if (!$data) {
			$this->clearAccessCookie();
			return false;
		}

		$code    = (string) ($data['code'] ?? '');
		$expires = (int)    ($data['expires'] ?? 0);

		if (!$code || !$expires || time() > $expires) {
			$this->clearAccessCookie();
			return false;
		}

		$codes = $this->parseCodes();
		if (!isset($codes[$code])) {
			$this->clearAccessCookie();
			return false;
		}

		return true;
	}

	protected function setAccessCookie($code, $expires) {
		$value = $this->encodeSignedCookie([
			'code'    => (string) $code,
			'expires' => (int) $expires,
		]);

		$this->setCookie($this->getAccessCookieName(), $value, (int) $expires);
		$_COOKIE[$this->getAccessCookieName()] = $value;
	}

	protected function clearAccessCookie() {
		$this->setCookie($this->getAccessCookieName(), '', time() - 3600);
		unset($_COOKIE[$this->getAccessCookieName()]);
	}

	protected function setErrorCookie() {
		$this->setCookie($this->getErrorCookieName(), '1', time() + 300);
		$_COOKIE[$this->getErrorCookieName()] = '1';
	}

	protected function clearErrorCookie() {
		$this->setCookie($this->getErrorCookieName(), '', time() - 3600);
		unset($_COOKIE[$this->getErrorCookieName()]);
	}

	protected function encodeSignedCookie(array $data) {
		$secret = $this->getCookieSecret();
		if ($secret === '') return '';
		$payload = $this->base64UrlEncode(json_encode($data));
		$signature = hash_hmac('sha256', $payload, $secret);

		return $payload . '.' . $signature;
	}

	protected function decodeSignedCookie($value) {
		$secret = $this->getCookieSecret();
		if ($secret === '' || !is_string($value) || strlen($value) > 8192) return null;
		$parts = explode('.', $value, 2);
		if (count($parts) !== 2) return null;

		[$payload, $signature] = $parts;
		$expected = hash_hmac('sha256', $payload, $secret);
		if (!hash_equals($expected, $signature)) return null;

		$base64 = strtr($payload, '-_', '+/');
		$base64 .= str_repeat('=', (4 - strlen($base64) % 4) % 4);
		$json = base64_decode($base64, true);
		if ($json === false) return null;

		$data = json_decode($json, true);
		return is_array($data) ? $data : null;
	}

	protected function base64UrlEncode($value) {
		return rtrim(strtr(base64_encode((string) $value), '+/', '-_'), '=');
	}

	protected function getCookieSecret() {
		$config = $this->wire('config');
		$salt = (string) $config->userAuthSalt;

		// Never sign a credential with a predictable session name or file path.
		return $salt !== '' ? $salt . '|InviteAccess' : '';
	}

	protected function getAccessCookieName() {
		return 'invite_access';
	}

	protected function getErrorCookieName() {
		return 'invite_access_error';
	}

	protected function setCookie($name, $value, $expires) {
		if (headers_sent()) return;

		$options = [
			'expires'  => (int) $expires,
			'path'     => (string) $this->wire('config')->urls->root ?: '/',
			'secure'   => (bool) $this->wire('config')->https || (!empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off'),
			'httponly' => true,
			'samesite' => 'Lax',
		];

		setcookie($name, $value, $options);
	}

	protected function redirect($url) {
		if (!headers_sent()) {
			header('Cache-Control: no-store, private');
			header('Location: ' . $this->getRedirectPath($url), true, 303);
		}
	}

	/** Reject ambiguous paths rather than guessing how the web server will route them. */
	protected function normalizeRequestPath($url) {
		if (!is_string($url) || strlen($url) > 8192) return null;
		$path = explode('?', $url, 2)[0];
		if (preg_match('/%(?![0-9a-f]{2})/i', $path)) return null;
		$path = rawurldecode($path);
		if ($path === '' || $path[0] !== '/' || strpos($path, '//') !== false) return null;
		// Reject controls, backslashes, fragments, and nested percent encodings.
		if (preg_match('/[\x00-\x20\x7f\\\\#%?]/', $path)) return null;
		foreach (explode('/', $path) as $segment) {
			if ($segment === '.' || $segment === '..') return null;
		}
		return $path;
	}

	protected function pathMatches($path, $prefix) {
		$prefix = $this->normalizeRequestPath($prefix);
		if ($path === null || $prefix === null) return false;
		$prefix = rtrim($prefix, '/');
		// Selecting the homepage must not exempt the entire site.
		if ($prefix === '') return false;
		return $path === $prefix || strpos($path, $prefix . '/') === 0;
	}

	protected function getRedirectPath($url) {
		$path = $this->normalizeRequestPath($url);
		if ($path === null) return '/';
		return implode('/', array_map('rawurlencode', explode('/', $path)));
	}

	/** Signed double-submit token also works when guest sessions are disabled. */
	protected function getFormToken() {
		$name = $this->getAccessCookieName() . '_csrf';
		$token = $_COOKIE[$name] ?? '';
		$data = $this->decodeSignedCookie($token);
		if (!$data || ($data['purpose'] ?? '') !== 'csrf' || (int) ($data['expires'] ?? 0) <= time()) {
			$expires = time() + 3600;
			$token = $this->encodeSignedCookie([
				'purpose' => 'csrf', 'nonce' => bin2hex(random_bytes(32)), 'expires' => $expires,
			]);
			$this->setCookie($name, $token, $expires);
			$_COOKIE[$name] = $token;
		}
		return $token;
	}

	protected function hasValidFormToken() {
		$cookie = $_COOKIE[$this->getAccessCookieName() . '_csrf'] ?? '';
		$posted = $this->wire('input')->post('invite_access_csrf');
		if (!is_string($cookie) || !is_string($posted) || $cookie === '' || !hash_equals($cookie, $posted)) return false;
		$data = $this->decodeSignedCookie($cookie);
		return $data && ($data['purpose'] ?? '') === 'csrf'
			&& is_string($data['nonce'] ?? null) && strlen($data['nonce']) === 64
			&& (int) ($data['expires'] ?? 0) > time();
	}

	/*
	 * ─────────────────────────────────────────────
	 * Config-File Overrides → per-environment settings
	 *
	 * Module settings live in the database, so a database copied between
	 * environments carries the gate's state with it. A config file does not
	 * travel that way, so settings pinned there hold per environment:
	 *
	 *   $config->inviteAccess = ['enabled' => false];   // site/config-dev.php
	 *
	 * Any key from getDefaultData() may be set; other keys are ignored. The
	 * overrides are applied to the instance the hook runs on, at check time,
	 * and are never written back. Same idea as TracyDebugger's $config->tracy.
	 * ─────────────────────────────────────────────
	 */
	protected function applyConfigOverrides() {
		foreach (self::configOverrides($this->wire('config')) as $key => $value) {
			$this->$key = $value;
		}
	}

	/** The entries of $config->inviteAccess that name a module setting. */
	protected static function configOverrides($config) {
		$overrides = $config->inviteAccess ?? null;
		if (!is_array($overrides)) return [];
		return array_intersect_key($overrides, self::getDefaultData());
	}

	/*
	 * ─────────────────────────────────────────────
	 * Parse Invite Codes → ['code' => 'Label', ...]
	 * ─────────────────────────────────────────────
	 */
	protected function parseCodes() {
		$result = [];
		$raw    = trim((string) $this->inviteCodes);
		if (!$raw) return $result;

		foreach (explode("\n", $raw) as $line) {
			$line = trim($line);
			if (!$line || strpos($line, '#') === 0) continue;

			if (strpos($line, '|') !== false) {
				[$code, $label] = array_map('trim', explode('|', $line, 2));
			} else {
				$code  = $line;
				$label = $line;
			}

			if ($code) $result[$code] = $label;
		}

		return $result;
	}

	/*
	 * ─────────────────────────────────────────────
	 * Parse Allowed Paths → ['/api/webhooks/stripe/', ...]
	 *
	 * Lines are site-relative, like $page->path, and are resolved against
	 * the installation root. A line that normalizeRequestPath() rejects, or
	 * that resolves to the root itself, is ignored rather than guessed at;
	 * $ignored receives those lines so the config screen can name them.
	 * ─────────────────────────────────────────────
	 */
	protected function parseAllowedPaths(&$ignored = [], $root = null) {
		$result  = [];
		$ignored = [];
		$raw     = trim((string) $this->allowedPaths);
		if (!$raw) return $result;

		$root = rtrim((string) ($root ?? $this->wire('config')->urls->root), '/');
		foreach (explode("\n", $raw) as $line) {
			$line = trim($line);
			if (!$line || strpos($line, '#') === 0) continue;

			$path = $this->normalizeRequestPath($root . ($line[0] === '/' ? $line : '/' . $line));
			// The installation root would exempt the entire site.
			if ($path === null || rtrim($path, '/') === $root) {
				$ignored[] = $line;
				continue;
			}
			$result[] = $path;
		}

		return $result;
	}

	/** The configured prefix a request path falls under, or null when it falls under none. */
	protected function matchAllowedPath($path) {
		foreach ($this->parseAllowedPaths() as $prefix) {
			if ($this->pathMatches($path, $prefix)) return $prefix;
		}
		return null;
	}

	/** Opt-in trail of gate bypasses, kept out of the capped JSON access log. */
	protected function logAllowedPath($prefix, $path) {
		if (!$this->logAllowedPaths) return;
		$method = (string) ($_SERVER['REQUEST_METHOD'] ?? '');
		$this->wire('log')->save('invite-access', "allowed path: {$method} {$path} matched {$prefix} from " . $this->getClientIP());
	}

	/*
	 * ─────────────────────────────────────────────
	 * Access Log
	 * ─────────────────────────────────────────────
	 */
	protected function writeLog($code, $label, $success, $requestUrl = '') {
		if (!$this->logEnabled) return;

		$logPath = trim((string) $this->logPath)
			?: $this->wire('config')->paths->assets . 'logs/invite-access.json';

		$entry = [
			'time'       => date('Y-m-d H:i:s'),
			'timestamp'  => time(),
			'success'    => (bool) $success,
			'code'       => $success ? $code : '(invalid: ' . substr($code, 0, 20) . ')',
			'code_label' => $label ?: '—',
			'ip'         => $this->getClientIP(),
			'ua'         => substr((string) ($_SERVER['HTTP_USER_AGENT'] ?? ''), 0, 200),
			'url'        => $requestUrl ?: (string) ($_SERVER['REQUEST_URI'] ?? ''),
		];

		$dir = dirname($logPath);
		if (!is_dir($dir)) wireMkdir($dir);

		// Lock a stable sidecar: the data file itself is atomically replaced below.
		$lock = @fopen($logPath . '.lock', 'c');
		if (!$lock) return;
		$tmp = null;
		try {
			if (!flock($lock, LOCK_EX)) return;
			$entries = [];
			if (is_file($logPath)) {
				$raw = file_get_contents($logPath);
				$entries = $raw === '' ? [] : json_decode($raw, true);
				if (!is_array($entries) || array_values($entries) !== $entries) {
					error_log('InviteAccess: invalid access log; preserved without overwriting.');
					return;
				}
			}
			array_unshift($entries, $entry);
			$entries = array_slice($entries, 0, 1000);
			$json = json_encode($entries, JSON_PRETTY_PRINT | JSON_UNESCAPED_UNICODE | JSON_INVALID_UTF8_SUBSTITUTE);
			if ($json === false) return;
			$tmp = tempnam($dir, '.invite-access-');
			if ($tmp === false) return;
			chmod($tmp, 0600);
			if (file_put_contents($tmp, $json) !== strlen($json) || !rename($tmp, $logPath)) {
				error_log('InviteAccess: could not commit access log.');
			}
		} finally {
			if ($tmp && is_file($tmp)) unlink($tmp);
			flock($lock, LOCK_UN);
			fclose($lock);
		}
	}

	protected function getClientIP() {
		// Forwarded headers are untrusted without a deployment-specific proxy allowlist.
		$ip = (string) ($_SERVER['REMOTE_ADDR'] ?? '');
		return filter_var($ip, FILTER_VALIDATE_IP) ? $ip : '0.0.0.0';
	}

	/*
	 * ─────────────────────────────────────────────
	 * Render Invite Form
	 * ─────────────────────────────────────────────
	 */
	protected function renderInviteForm() {
		$session  = $this->wire('session');
		$hasError = (bool) $session->get('invite_access_error') || (bool) ($_COOKIE[$this->getErrorCookieName()] ?? false);
		if ($hasError) $session->remove('invite_access_error');
		if ($hasError) $this->clearErrorCookie();

		$title   = htmlspecialchars((string) $this->pageTitle   ?: 'Access Required');
		$message = htmlspecialchars((string) $this->pageMessage ?: 'Please enter your invite code to continue.');
		$error   = htmlspecialchars((string) $this->errorMessage ?: 'Invalid invite code. Please try again.');
		$button  = htmlspecialchars((string) $this->buttonLabel ?: 'Continue');

		$styleMap = [
			'red'   => ['light' => '#e8265e', 'dark' => '#ff4d80'],
			'blue'  => ['light' => '#1a6cf6', 'dark' => '#4d8fff'],
			'green' => ['light' => '#1a9e5c', 'dark' => '#2ecc82'],
			'black' => ['light' => '#111111', 'dark' => '#eeeeee'],
		];
		$style      = (string) $this->style;
		$accentL    = $styleMap[$style]['light']  ?? $styleMap['red']['light'];
		$accentD    = $styleMap[$style]['dark']   ?? $styleMap['red']['dark'];

		$errorHtml = $hasError
			? "<div class='ia-error'><i class='bi bi-exclamation-circle'></i> {$error}</div>"
			: '';

		$tokenName = 'invite_access_csrf';
		$tokenValue = htmlspecialchars($this->getFormToken(), ENT_QUOTES, 'UTF-8');

		return <<<HTML
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{$title}</title>
<link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/bootstrap-icons@1.11.3/font/bootstrap-icons.min.css">
<style>
  @import url('https://cdn.jsdelivr.net/npm/@fontsource/apfel-grotezk@5.1.1/index.css');

  :root {
	--bg:       #eceae5;
	--card:     #ffffff;
	--text:     #111111;
	--muted:    #6b6b6b;
	--border:   #e0ddd8;
	--accent:   {$accentL};
	--input-bg: #f5f4f1;
	--ph:       #b0ada8;
	--radius:   5px;
  }
  [data-theme="dark"] {
	--bg:       #181818;
	--card:     #222222;
	--text:     #f0f0f0;
	--muted:    #888888;
	--border:   #303030;
	--accent:   {$accentD};
	--input-bg: #2a2a2a;
	--ph:       #555555;
  }

  *, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }
  html { height: 100%; }

  body {
	font-family: 'Apfel Grotezk', system-ui, sans-serif;
	background: var(--bg);
	color: var(--text);
	min-height: 100%;
	display: flex;
	flex-direction: column;
	align-items: center;
	justify-content: center;
	padding: 24px 16px;
	transition: background .25s, color .25s;
  }

  /* ── theme toggle ── */
  .ia-toggle {
	position: fixed;
	top: 16px;
	right: 16px;
	display: flex;
	gap: 2px;
	background: var(--card);
	border: 1px solid var(--border);
	border-radius: var(--radius);
	padding: 3px;
	z-index: 10;
	transition: background .25s, border-color .25s;
  }
  .ia-toggle button {
	background: none;
	border: none;
	cursor: pointer;
	color: var(--muted);
	font-size: 13px;
	width: 28px;
	height: 28px;
	display: grid;
	place-items: center;
	border-radius: calc(var(--radius) - 1px);
	transition: color .15s, background .15s;
  }
  .ia-toggle button.active { background: var(--text); color: var(--bg); }
  .ia-toggle button:not(.active):hover { color: var(--text); }

  /* ── wrapper — same width as card ── */
  .ia-wrap {
	width: 100%;
	max-width: 380px;
  }

  /* ── heading — same max-width as card ── */
  .ia-heading {
	font-size: clamp(32px, 9vw, 52px);
	font-weight: 800;
	line-height: 1.08;
	letter-spacing: -.03em;
	margin-bottom: 20px;
  }

  /* ── white card ── */
  .ia-card {
	background: var(--card);
	border-radius: var(--radius);
	padding: 24px;
	box-shadow: 0 1px 4px rgba(0,0,0,.07), 0 0 0 1px rgba(0,0,0,.05);
	transition: background .25s;
  }

  .ia-card-sub {
	font-size: 14px;
	color: var(--muted);
	margin-bottom: 20px;
	line-height: 1.55;
  }

  /* ── error ── */
  .ia-error {
	display: flex;
	align-items: center;
	gap: 8px;
	font-size: 13px;
	color: var(--accent);
	background: color-mix(in srgb, var(--accent) 8%, transparent);
	border: 1px solid color-mix(in srgb, var(--accent) 20%, transparent);
	border-radius: var(--radius);
	padding: 10px 12px;
	margin-bottom: 16px;
  }

  /* ── field ── */
  .ia-label {
	display: block;
	font-size: 13px;
	font-weight: 600;
	margin-bottom: 6px;
  }
  .ia-input {
	width: 100%;
	background: var(--input-bg);
	border: 1.5px solid var(--border);
	border-radius: var(--radius);
	padding: 11px 13px;
	font-size: 15px;
	font-family: inherit;
	color: var(--text);
	outline: none;
	transition: border-color .15s, background .25s;
	-webkit-appearance: none;
  }
  .ia-input:focus { border-color: var(--accent); background: var(--card); }
  .ia-input::placeholder { color: var(--ph); }

  /* ── button ── */
  .ia-btn {
	display: flex;
	align-items: center;
	justify-content: center;
	gap: 8px;
	width: 100%;
	margin-top: 12px;
	background: var(--accent);
	color: #fff;
	border: none;
	border-radius: var(--radius);
	padding: 13px;
	font-family: inherit;
	font-size: 15px;
	font-weight: 600;
	cursor: pointer;
	transition: filter .15s;
  }
  .ia-btn:hover { filter: brightness(1.08); }
  .ia-btn:active { filter: brightness(.94); }

  /* ── tablet+ ── */
  @media (min-width: 480px) {
	body { padding: 40px 24px; }
	.ia-card { padding: 32px; }
	.ia-toggle { top: 20px; right: 20px; }
  }
</style>
</head>
<body>

<div class="ia-toggle" role="group" aria-label="Color theme">
  <button id="btn-light" title="Light" onclick="setTheme('light')"><i class="bi bi-sun"></i></button>
  <button id="btn-auto"  title="Auto"  onclick="setTheme('auto')"><i class="bi bi-circle-half"></i></button>
  <button id="btn-dark"  title="Dark"  onclick="setTheme('dark')"><i class="bi bi-moon"></i></button>
</div>

<div class="ia-wrap">
  <h1 class="ia-heading">{$title}</h1>

  <div class="ia-card">
	<p class="ia-card-sub">{$message}</p>

	{$errorHtml}

	<form method="post" autocomplete="off" novalidate>
	  <input type="hidden" name="{$tokenName}" value="{$tokenValue}">
	  <label class="ia-label" for="invite_code">Invite Code</label>
	  <input class="ia-input" type="password" id="invite_code" name="invite_code"
			 placeholder="Enter your invite code" autofocus spellcheck="false"
			 autocomplete="off">
	  <button class="ia-btn" type="submit">
		{$button} <i class="bi bi-arrow-right"></i>
	  </button>
	</form>
  </div>
</div>

<script>
  const STORAGE_KEY = 'ia-theme';
  const mql = window.matchMedia('(prefers-color-scheme: dark)');

  function applyTheme(pref) {
	const isDark = pref === 'dark' || (pref === 'auto' && mql.matches);
	document.documentElement.setAttribute('data-theme', isDark ? 'dark' : 'light');
	['light', 'auto', 'dark'].forEach(t => {
	  document.getElementById('btn-' + t).classList.toggle('active', t === pref);
	});
  }

  function setTheme(pref) {
	localStorage.setItem(STORAGE_KEY, pref);
	applyTheme(pref);
  }

  const saved = localStorage.getItem(STORAGE_KEY) || 'auto';
  applyTheme(saved);

  mql.addEventListener('change', () => {
	if ((localStorage.getItem(STORAGE_KEY) || 'auto') === 'auto') applyTheme('auto');
  });
</script>
</body>
</html>
HTML;
	}

	/*
	 * ─────────────────────────────────────────────
	 * Module Config Fields
	 * ─────────────────────────────────────────────
	 */
	public static function getModuleConfigInputfields(array $data) {
		$data    = array_merge(self::getDefaultData(), $data);
		$modules = wire('modules');
		$fields  = new InputfieldWrapper();

		$overridden = array_keys(self::configOverrides(wire('config')));
		if ($overridden) {
			$f = $modules->get('InputfieldMarkup');
			$f->label = 'Overridden by $config->inviteAccess';
			$f->value = '<p>Set in a config file for this environment and used instead of the saved values: <code>'
				. implode('</code>, <code>', array_map('htmlspecialchars', $overridden))
				. '</code>. Edits below are saved but not applied here while the override is in place.</p>';
			$fields->add($f);
		}

		$f = $modules->get('InputfieldCheckbox');
		$f->name  = 'enabled';
		$f->label = 'Enable Invite Access';
		$f->description = 'When checked, visitors must enter a valid invite code to view the site.';
		$f->value = 1;
		$f->attr('checked', $data['enabled'] ? 'checked' : '');
		$fields->add($f);

		$f = $modules->get('InputfieldTextarea');
		$f->name        = 'inviteCodes';
		$f->label       = 'Invite Codes';
		$f->description = 'One code per line. Optionally add a label after a pipe: `agency-secret-42|Agency Team`. Lines starting with # are ignored.';
		$f->notes       = "Example:\nSUMMER2025|Summer Campaign\nAGENCY-PREVIEW|Agency Team\nCLIENT-ACCESS|Client Preview";
		$f->rows        = 8;
		$f->attr('value', $data['inviteCodes']);
		$fields->add($f);

		$f = $modules->get('InputfieldText');
		$f->name        = 'pageTitle';
		$f->label       = 'Access Page Title';
		$f->attr('value', $data['pageTitle']);
		$f->columnWidth = 50;
		$fields->add($f);

		$f = $modules->get('InputfieldInteger');
		$f->name        = 'sessionHours';
		$f->label       = 'Session Duration (hours)';
		$f->description = 'How long before a visitor must re-enter their code.';
		$f->attr('value', $data['sessionHours']);
		$f->columnWidth = 50;
		$fields->add($f);

		$f = $modules->get('InputfieldText');
		$f->name        = 'pageMessage';
		$f->label       = 'Message on Access Page';
		$f->attr('value', $data['pageMessage']);
		$f->columnWidth = 50;
		$fields->add($f);

		$f = $modules->get('InputfieldText');
		$f->name        = 'errorMessage';
		$f->label       = 'Error Message (invalid code)';
		$f->attr('value', $data['errorMessage']);
		$f->columnWidth = 50;
		$fields->add($f);

		$f = $modules->get('InputfieldText');
		$f->name        = 'buttonLabel';
		$f->label       = 'Button Label';
		$f->attr('value', $data['buttonLabel']);
		$f->columnWidth = 50;
		$fields->add($f);

		$f = $modules->get('InputfieldRadios');
		$f->name        = 'style';
		$f->label       = 'Style';
		$f->description = 'Accent color used for the button and input focus border.';
		$f->addOption('red',   'Red');
		$f->addOption('blue',  'Blue');
		$f->addOption('green', 'Green');
		$f->addOption('black', 'Black');
		$f->attr('value', $data['style'] ?: 'red');
		$f->optionColumns = 1;
		$f->columnWidth = 50;
		$fields->add($f);

		$f = $modules->get('InputfieldPageListSelectMultiple');
		$f->name        = 'allowedPages';
		$f->label       = 'Always Accessible Pages';
		$f->description = 'These pages and descendants bypass the invite check. Stored page IDs are local to this database: reselect and verify them after importing configuration into another site.';
		$f->attr('value', $data['allowedPages']);
		$f->set('unselectLabel', 'Unselect');
		if (empty($data['allowedPages'])) $f->collapsed = Inputfield::collapsedYes;
		$fields->add($f);

		$f = $modules->get('InputfieldTextarea');
		$f->name        = 'allowedPaths';
		$f->label       = 'Always Accessible Paths';
		$f->description = 'One path per line, relative to the ProcessWire root. The path and its descendants bypass the invite check. Meant for endpoints that verify their own secrets, such as payment or booking webhooks: without an exception the gate answers them with the invite form and HTTP 200, so the sender records a delivery that never ran. Lines starting with # are ignored.';
		$f->notes       = "Example:\n/api/webhooks/stripe/\n/api/webhooks/beds24/";
		$f->rows        = 4;
		$f->attr('value', $data['allowedPaths']);
		$module = new self; // not the live instance: defaults only, root passed in explicitly
		$module->allowedPaths = $data['allowedPaths'];
		$ignored = [];
		$module->parseAllowedPaths($ignored, wire('config')->urls->root);
		if ($ignored) $f->notes = 'Ignored, not usable as a path: ' . implode(', ', $ignored) . "\n\n" . $f->notes;
		if (empty($data['allowedPaths'])) $f->collapsed = Inputfield::collapsedYes;
		$fields->add($f);

		$fieldset = $modules->get('InputfieldFieldset');
		$fieldset->label = 'Access Log';

			$f = $modules->get('InputfieldCheckbox');
			$f->name  = 'logEnabled';
			$f->label = 'Enable access logging';
			$f->value = 1;
			$f->attr('checked', $data['logEnabled'] ? 'checked' : '');
			$fieldset->add($f);

			$f = $modules->get('InputfieldCheckbox');
			$f->name  = 'logAllowedPaths';
			$f->label = 'Log requests that bypass the gate through an allowed path';
			$f->description = 'One line per request in the ProcessWire log "invite-access" (Setup › Logs): method, path, the matching prefix and REMOTE_ADDR. Kept out of the JSON access log so webhook traffic cannot push invite attempts out of the capped file.';
			$f->value = 1;
			$f->attr('checked', $data['logAllowedPaths'] ? 'checked' : '');
			$fieldset->add($f);

			$f = $modules->get('InputfieldText');
			$f->name        = 'logPath';
			$f->label       = 'Log file path (optional)';
			$f->description = 'Absolute path to JSON log file. Leave empty to use site/assets/logs/invite-access.json';
			$f->attr('value', $data['logPath']);
			if (!$data['logPath']) $f->collapsed = Inputfield::collapsedYes;
			$fieldset->add($f);

		$fields->add($fieldset);

		// Log viewer
		$logPath   = $data['logPath'] ?: wire('config')->paths->assets . 'logs/invite-access.json';
		$logExists = is_file($logPath);
		$logPathHtml = htmlspecialchars($logPath, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');

		$f = $modules->get('InputfieldMarkup');
		$f->label = 'Recent Access Log';

		if ($logExists) {
			$entries = json_decode(file_get_contents($logPath), true);
			if (!is_array($entries)) $entries = [];
			$rows = '';
			foreach (array_slice($entries, 0, 50) as $e) {
				$status = $e['success']
					? "<span style='color:#4ade80'>&#10004; granted</span>"
					: "<span style='color:#f87171'>&#10008; denied</span>";
				$rows .= "<tr>
					<td style='white-space:nowrap;padding:5px 8px'>" . htmlspecialchars((string)$e['time']) . "</td>
					<td style='padding:5px 8px'>{$status}</td>
					<td style='padding:5px 8px'><code>" . htmlspecialchars((string)$e['code']) . "</code></td>
					<td style='padding:5px 8px'>" . htmlspecialchars((string)($e['code_label']??'—')) . "</td>
					<td style='padding:5px 8px'>" . htmlspecialchars((string)$e['ip']) . "</td>
					<td style='padding:5px 8px;font-size:11px;color:#888'>" . htmlspecialchars((string)($e['url']??'')) . "</td>
					<td style='padding:5px 8px;font-size:11px;color:#888'>" . htmlspecialchars(substr((string)($e['ua']??''),0,60)) . "</td>
				</tr>";
			}
			$count = count($entries);
			$f->value = "
				<p style='margin-bottom:10px;color:#888;font-size:13px'>Showing last 50 of {$count} entries. Log: <code>{$logPathHtml}</code></p>
				<div style='overflow-x:auto'>
				<table style='width:100%;border-collapse:collapse;font-size:13px'>
					<thead>
						<tr style='border-bottom:2px solid #ddd;text-align:left'>
							<th style='padding:6px 8px'>Time</th>
							<th style='padding:6px 8px'>Status</th>
							<th style='padding:6px 8px'>Code</th>
							<th style='padding:6px 8px'>Label</th>
							<th style='padding:6px 8px'>IP</th>
							<th style='padding:6px 8px'>URL</th>
							<th style='padding:6px 8px'>User Agent</th>
						</tr>
					</thead>
					<tbody>{$rows}</tbody>
				</table>
				</div>";
		} else {
			$f->value = "<p style='color:#888'>No log entries yet. Log file will be created at: <code>{$logPathHtml}</code></p>";
		}
		$fields->add($f);

		return $fields;
	}
}
