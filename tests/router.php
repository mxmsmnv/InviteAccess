<?php namespace ProcessWire;
require __DIR__ . '/bootstrap.php';
if (getenv('INVITE_TEST_SESSION') === '1') session_start();
$m = testModule();
if (getenv('INVITE_TEST_OVERRIDE') === '1') $m->api['config']->inviteAccess = ['enabled' => false];
$m->checkAccess(new HookEvent);
header('Content-Type: text/plain');
echo 'GATED CONTENT';
