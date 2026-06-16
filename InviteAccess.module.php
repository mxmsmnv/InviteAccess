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
 * - Superuser always bypasses
 * - Configurable allowed pages (e.g. assets, API endpoints)
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
			'version'   => 102,
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
			'inviteCodes'    => "SUMMER2025|Summer Campaign\nAGENCY-PREVIEW|Agency Team\nCLIENT-ACCESS|Client Preview",
			'pageTitle'      => 'Access Required',
			'pageMessage'    => 'Please enter your invite code to continue.',
			'errorMessage'   => 'Invalid invite code. Please try again.',
			'buttonLabel'    => 'Continue',
			'style'          => 'red',
			'sessionHours'   => 1,
			'logEnabled'     => 1,
			'logPath'        => '',
			'allowedPages'   => [],
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
		if (!$this->enabled) return;

		$user = $this->wire('user');

		// Logged-in users always pass
		if ($user->isLoggedIn()) return;

		// Current request URL (before any PW routing)
		$requestUrl = (string) ($_SERVER['REQUEST_URI'] ?? '/');
		$adminUrl   = rtrim((string) $this->wire('config')->urls->admin, '/');

		// Skip PW admin
		if ($adminUrl && strpos($requestUrl, $adminUrl) === 0) return;

		// Skip explicitly allowed pages
		if (!empty($this->allowedPages) && is_array($this->allowedPages)) {
			foreach ($this->allowedPages as $pid) {
				$pid = (int) $pid;
				if (!$pid) continue;
				$p = $this->wire('pages')->get($pid);
				if ($p && $p->id) {
					$pUrl = rtrim((string) $p->url, '/');
					if ($pUrl && strpos($requestUrl, $pUrl) === 0) return;
				}
			}
		}

		// Check existing valid session
		if ($this->hasValidSession()) return;

		// Handle form submission
		$postedCode = (string) $this->wire('input')->post('invite_code');
		if ($postedCode !== '') {
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
		$entered = trim($entered);
		$codes   = $this->parseCodes();

		foreach ($codes as $code => $label) {
			if (hash_equals($code, $entered)) {
				$expires = time() + ((int) $this->sessionHours * 3600);
				$session->set('invite_access_code',    $code);
				$session->set('invite_access_expires', $expires);
				$this->setAccessCookie($code, $expires);
				$this->clearErrorCookie();

				$this->writeLog($code, $label, true, $requestUrl);

				// PRG — redirect back to the same URL (minus query string)
				$redirectTo = strtok($requestUrl, '?') ?: '/';
				$this->redirect($redirectTo);
				exit;
			}
		}

		// Invalid
		$this->writeLog($entered, '', false, $requestUrl);
		$session->set('invite_access_error', 1);
		$this->setErrorCookie();

		$redirectTo = strtok($requestUrl, '?') ?: '/';
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
		$cookie = (string) ($_COOKIE[$this->getAccessCookieName()] ?? '');
		if (!$cookie) return false;

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
		$payload = $this->base64UrlEncode(json_encode($data));
		$signature = hash_hmac('sha256', $payload, $this->getCookieSecret());

		return $payload . '.' . $signature;
	}

	protected function decodeSignedCookie($value) {
		$parts = explode('.', (string) $value, 2);
		if (count($parts) !== 2) return null;

		[$payload, $signature] = $parts;
		$expected = hash_hmac('sha256', $payload, $this->getCookieSecret());
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
		$salt = (string) ($config->userAuthSalt ?: $config->sessionName ?: __FILE__);

		return $salt . '|InviteAccess';
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
			'path'     => '/',
			'secure'   => (!empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off'),
			'httponly' => true,
			'samesite' => 'Lax',
		];

		setcookie($name, $value, $options);
	}

	protected function redirect($url) {
		if (!headers_sent()) {
			header('Location: ' . $url, true, 303);
		}
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

		$entries = [];
		if (is_file($logPath)) {
			$raw = file_get_contents($logPath);
			if ($raw) $entries = json_decode($raw, true) ?: [];
		}

		array_unshift($entries, $entry);
		if (count($entries) > 1000) $entries = array_slice($entries, 0, 1000);

		$dir = dirname($logPath);
		if (!is_dir($dir)) wireMkdir($dir);

		file_put_contents($logPath, json_encode($entries, JSON_PRETTY_PRINT | JSON_UNESCAPED_UNICODE));
	}

	protected function getClientIP() {
		foreach (['HTTP_CF_CONNECTING_IP', 'HTTP_X_FORWARDED_FOR', 'REMOTE_ADDR'] as $key) {
			if (!empty($_SERVER[$key])) {
				$ip = trim(explode(',', $_SERVER[$key])[0]);
				if (filter_var($ip, FILTER_VALIDATE_IP)) return $ip;
			}
		}
		return '0.0.0.0';
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

		$tokenName  = $this->wire('session')->CSRF->getTokenName();
		$tokenValue = $this->wire('session')->CSRF->getTokenValue();

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
		$f->description = 'These pages bypass the invite check (e.g. a public landing page or API endpoint).';
		$f->attr('value', $data['allowedPages']);
		$f->set('unselectLabel', 'Unselect');
		if (empty($data['allowedPages'])) $f->collapsed = Inputfield::collapsedYes;
		$fields->add($f);

		$fieldset = $modules->get('InputfieldFieldset');
		$fieldset->label = 'Access Log';

			$f = $modules->get('InputfieldCheckbox');
			$f->name  = 'logEnabled';
			$f->label = 'Enable access logging';
			$f->value = 1;
			$f->attr('checked', $data['logEnabled'] ? 'checked' : '');
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

		$f = $modules->get('InputfieldMarkup');
		$f->label = 'Recent Access Log';

		if ($logExists) {
			$entries = json_decode(file_get_contents($logPath), true) ?: [];
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
				<p style='margin-bottom:10px;color:#888;font-size:13px'>Showing last 50 of {$count} entries. Log: <code>{$logPath}</code></p>
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
			$f->value = "<p style='color:#888'>No log entries yet. Log file will be created at: <code>{$logPath}</code></p>";
		}
		$fields->add($f);

		return $fields;
	}
}
