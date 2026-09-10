<?php namespace ProcessWire;
require __DIR__ . '/bootstrap.php';
if (getenv('INVITE_TEST_SESSION') === '1') session_start();
$m = testModule();
$m->checkAccess(new HookEvent);
header('Content-Type: text/plain');
echo 'GATED CONTENT';
