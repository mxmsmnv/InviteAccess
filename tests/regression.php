<?php namespace ProcessWire;
require __DIR__ . '/bootstrap.php';
set_error_handler(function($severity, $message, $file, $line) {
	if (error_reporting() & $severity) throw new \ErrorException($message, 0, $severity, $file, $line);
	return false;
});
$checks = 0;
function check($condition, $message) {
	global $checks;
	if (!$condition) throw new \RuntimeException($message);
	$checks++;
}
$m = testModule();
if (($argv[1] ?? '') === 'log-worker') {
	$m->logEnabled = 1;
	$m->logPath = $argv[2];
	for ($i = 0; $i < 40; $i++) $m->call('writeLog', 'test', 'Worker', true, '/' . $argv[3] . '/' . $i);
	exit;
}
foreach (['//evil.test/', '/\\evil.test/', '/%2fevil.test/', '/processwire/../private',
	'/processwire/%2e%2e/private', '/processwire/%252e%252e/private', '/processwire//private',
	'/processwire/%5c../private', '/%0d%0aLocation:evil', 'https://evil.test', '/%zz'] as $url) {
	check($m->call('normalizeRequestPath', $url) === null, 'Reject ambiguous URL: ' . $url);
	check($m->call('getRedirectPath', $url) === '/', 'Local fallback redirect: ' . $url);
}
foreach (['/processwire-other', '/press-release'] as $url) {
	$path = $m->call('normalizeRequestPath', $url);
	check(!$m->call('pathMatches', $path, '/processwire/'), 'Admin sibling stays gated');
	check(!$m->call('pathMatches', $path, '/press/'), 'Allowed page sibling stays gated');
}
check($m->call('pathMatches', '/processwire', '/processwire/'), 'Admin exact path');
check($m->call('pathMatches', '/processwire/edit/', '/processwire/'), 'Admin descendant');
check($m->call('pathMatches', '/press/item/', '/press/'), 'Allowed descendant');
check(!$m->call('pathMatches', '/private', '/'), 'Homepage must not exempt site');
check($m->call('getRedirectPath', '/caf%C3%A9/?secret=x') === '/caf%C3%A9/', 'Preserve encoding, remove query');

$_COOKIE = []; $_POST = [];
check(!$m->call('hasValidFormToken'), 'Missing CSRF denied');
$token = $m->call('getFormToken');
$_POST['invite_access_csrf'] = $token;
check($m->call('hasValidFormToken'), 'Signed double-submit accepted without a session');
$_COOKIE = [];
check(!$m->call('hasValidFormToken'), 'POST alone denied');
$_COOKIE['invite_access_csrf'] = $token;
$_POST['invite_access_csrf'] = $token . 'x';
check(!$m->call('hasValidFormToken'), 'Mismatched CSRF denied');
$expired = $m->call('encodeSignedCookie', ['purpose' => 'csrf', 'nonce' => str_repeat('a', 64), 'expires' => time() - 1]);
$_POST['invite_access_csrf'] = $_COOKIE['invite_access_csrf'] = $expired;
check(!$m->call('hasValidFormToken'), 'Expired CSRF denied');
$_POST['invite_access_csrf'] = $_COOKIE['invite_access_csrf'] = $m->call('encodeSignedCookie', ['code' => 'test-secret', 'expires' => time() + 60]);
check(!$m->call('hasValidFormToken'), 'Access cookie cannot serve as CSRF token');
$m->call('setAccessCookie', 'test-secret', time() + 60);
check($m->call('hasValidSession'), 'Access cookie grants with no persistent session');
$m->inviteCodes = 'replacement';
check(!$m->call('hasValidSession'), 'Removed code revokes access');
$m->api['config']->userAuthSalt = '';
check($m->call('encodeSignedCookie', ['code' => 'replacement']) === '', 'No predictable signing fallback');
check($m->call('decodeSignedCookie', $token) === null, 'No verification without secret');
$_COOKIE['invite_access_csrf'] = ['malformed'];
check($m->call('getFormToken') === '', 'Malformed cookie handled without warnings');

$_SERVER['REMOTE_ADDR'] = '127.0.0.1';
$_SERVER['HTTP_X_FORWARDED_FOR'] = '1.2.3.4';
$_SERVER['HTTP_CF_CONNECTING_IP'] = '5.6.7.8';
check($m->call('getClientIP') === '127.0.0.1', 'Ignore forged proxy headers');
$m = testModule();
$m->api = []; // CLI must return before reading any ProcessWire service.
$m->checkAccess(new HookEvent);
check(true, 'CLI bootstrap returns without gate output');

$m = testModule();
$data = InviteAccess::getDefaultData();
$data['logPath'] = sys_get_temp_dir() . '/<img src=x onerror=alert(1)>.json';
$fields = InviteAccess::getModuleConfigInputfields($data);
$html = end($fields->children)->value;
check(strpos($html, '<img') === false && strpos($html, '&lt;img') !== false, 'Missing log path escaped');
file_put_contents($data['logPath'], '[]');
try {
	$fields = InviteAccess::getModuleConfigInputfields($data);
	check(strpos(end($fields->children)->value, '<img') === false, 'Existing log path escaped');
} finally { unlink($data['logPath']); }

$log = tempnam(sys_get_temp_dir(), 'invite-test-');
$m->logEnabled = 1; $m->logPath = $log;
try {
	$workers = [];
	for ($i = 0; $i < 4; $i++) {
		$workers[] = proc_open([PHP_BINARY, __FILE__, 'log-worker', $log, (string) $i], [0 => ['file', '/dev/null', 'r'], 1 => ['file', '/dev/null', 'w'], 2 => STDERR], $pipes);
	}
	foreach ($workers as $worker) check(proc_close($worker) === 0, 'Log worker succeeds');
	$entries = json_decode(file_get_contents($log), true);
	check(count($entries) === 160, 'Concurrent writes retain all entries');
	check(count(array_unique(array_column($entries, 'url'))) === 160, 'Concurrent entries unique');
	file_put_contents($log, '[broken');
	$m->call('writeLog', 'x', 'x', false);
	check(file_get_contents($log) === '[broken', 'Corrupt history preserved');
	file_put_contents($log, json_encode(array_fill(0, 1000, ['url' => '/old'])));
	$_SERVER['HTTP_USER_AGENT'] = "invalid\xff";
	$m->call('writeLog', 'x', 'x', false, '/new');
	$entries = json_decode(file_get_contents($log), true);
	check(count($entries) === 1000 && $entries[0]['url'] === '/new', 'Cap and invalid UTF-8 handling');
} finally { unlink($log); @unlink($log . '.lock'); }
echo "PASS: $checks regression checks\n";
