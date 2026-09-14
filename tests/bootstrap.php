<?php namespace ProcessWire;

// Isolated doubles for the small ProcessWire API surface used by InviteAccess.
// These tests do not install a module or connect to a site's database.
interface Module {}
interface ConfigurableModule {}
class HookEvent {}
class WireData {
	private $data = [];
	public $api = [];
	public function __get($key) { return $this->data[$key] ?? null; }
	public function __set($key, $value) { $this->data[$key] = $value; }
	public function __isset($key) { return isset($this->data[$key]); }
	public function wire($key) { return $this->api[$key]; }
	public function set($key, $value) { $this->$key = $value; }
	public function get($key) { return $this->$key; }
	public function remove($key) { unset($this->data[$key]); }
}
class TestSession extends WireData {
	public function set($key, $value) {
		parent::set($key, $value);
		if (session_status() === PHP_SESSION_ACTIVE) $_SESSION[$key] = $value;
	}
	public function get($key) { return $_SESSION[$key] ?? parent::get($key); }
	public function remove($key) { parent::remove($key); unset($_SESSION[$key]); }
}
class TestInput { public function post($key) { return $_POST[$key] ?? null; } }
class TestUser { public function isLoggedIn() { return false; } }
class TestPages {
	public function get($id) { return (object) ['id' => $id, 'url' => '/press/']; }
}
class TestLog {
	public $entries = [];
	public function save($name, $text) { $this->entries[] = [$name, $text]; return true; }
}
class Inputfield extends WireData {
	const collapsedYes = 1;
	public $children = [];
	public function add($field) { $this->children[] = $field; }
	public function attr($name, $value) { $this->$name = $value; }
	public function addOption($value, $label) {}
}
class InputfieldWrapper extends Inputfield {}
class TestModules { public function get($name) { return new Inputfield; } }
function wire($key) { return $GLOBALS['testApi'][$key]; }
function wireMkdir($path) { return mkdir($path, 0700, true); }

require dirname(__DIR__) . '/InviteAccess.module.php';
class TestInviteAccess extends InviteAccess {
	public function call($method, ...$args) { return $this->$method(...$args); }
}
function testModule() {
	$m = new TestInviteAccess;
	$m->api = [
		'config' => (object) [
			'cli' => false, 'https' => false, 'userAuthSalt' => 'isolated-test-secret-only',
			'urls' => (object) ['admin' => '/processwire/', 'root' => '/'],
			'paths' => (object) ['assets' => sys_get_temp_dir() . '/'],
		],
		'session' => new TestSession, 'input' => new TestInput,
		'user' => new TestUser, 'pages' => new TestPages, 'modules' => new TestModules, 'log' => new TestLog,
	];
	$GLOBALS['testApi'] = $m->api;
	$m->enabled = 1;
	$m->inviteCodes = "test-secret|Test team\n123456|Numeric";
	$m->allowedPages = [123];
	$m->allowedPaths = "/hooks/stripe/\n# comment\nhooks/beds24";
	$m->logEnabled = 0;
	return $m;
}
