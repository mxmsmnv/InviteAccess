#!/usr/bin/env python3
"""HTTP regression tests against PHP's web SAPI and isolated ProcessWire doubles."""
import http.client
import os
from pathlib import Path
import re
import shutil
import socket
import subprocess
import tempfile
import time
from http.cookies import SimpleCookie
from urllib.parse import urlencode

ROOT = Path(__file__).resolve().parent
checks = 0


def check(condition, message):
    global checks
    assert condition, message
    checks += 1


for sessions, override in ((False, False), (True, False), (False, True)):
    with tempfile.TemporaryDirectory(prefix='invite-http-') as tmp:
        with socket.socket() as sock:
            sock.bind(('127.0.0.1', 0))
            port = sock.getsockname()[1]
        with open(Path(tmp) / 'server.log', 'w+') as log:
            server = subprocess.Popen(
                [shutil.which('php'), '-d', f'session.save_path={tmp}', '-S',
                 f'127.0.0.1:{port}', str(ROOT / 'router.php')],
                env={**os.environ, 'INVITE_TEST_SESSION': str(int(sessions)),
                     'INVITE_TEST_OVERRIDE': str(int(override))},
                stdout=log, stderr=log,
            )
            jar = {}

            def request(path='/', values=None):
                conn = http.client.HTTPConnection('127.0.0.1', port, timeout=5)
                headers = {'Cookie': '; '.join(f'{k}={v}' for k, v in jar.items())}
                if values is not None:
                    headers['Content-Type'] = 'application/x-www-form-urlencoded'
                conn.request('GET' if values is None else 'POST', path,
                             None if values is None else urlencode(values), headers)
                response = conn.getresponse()
                body = response.read().decode()
                for key, value in response.getheaders():
                    if key.lower() == 'set-cookie':
                        cookies = SimpleCookie(value)
                        jar.update({k: v.value for k, v in cookies.items()})
                result = response.status, dict(response.getheaders()), body
                conn.close()
                return result

            try:
                for attempt in range(50):
                    try:
                        with socket.create_connection(('127.0.0.1', port), timeout=.1):
                            break
                    except OSError:
                        if server.poll() is not None:
                            raise RuntimeError('PHP server exited')
                        time.sleep(.05)
                status, headers, body = request('/private/')
                if override:
                    check(body == 'GATED CONTENT', 'Config-file override keeps the gate off')
                    check(request('/private/', {'invite_code': 'wrong'})[2] == 'GATED CONTENT',
                          'No form handling while the gate is overridden off')
                else:
                    check('Access Required' in body, 'Anonymous request gated')
                    check(headers.get('Cache-Control') == 'no-store, private', 'Gate not cacheable')
                    token = re.search(r'name="invite_access_csrf" value="([^"]+)"', body)[1]
                    check(len(token) > 64, 'Signed CSRF rendered')
                    for path in ('/processwire/', '/processwire/edit/', '/press/', '/press/item/'):
                        check(request(path)[2] == 'GATED CONTENT', 'Intended exemption: ' + path)
                    for path in ('/hooks/stripe/', '/hooks/stripe/event/', '/hooks/beds24/'):
                        check(request(path)[2] == 'GATED CONTENT', 'Intended path exemption: ' + path)
                    check(request('/hooks/stripe/', {'payload': 'x'})[2] == 'GATED CONTENT',
                          'Webhook POST reaches the allowed path without an invite')
                    for path in ('/processwire-other/', '/press-release/', '/hooks/', '/hooks/stripe-old/',
                                 '/hooks/../private/', '/processwire/../private/',
                                 '/processwire/%2e%2e/private/', '/processwire/%252e%252e/private/',
                                 '/processwire//private/'):
                        check('Access Required' in request(path)[2], 'Bypass denied: ' + path)
                    check('Access Required' in request('/private/', {'invite_code': 'test-secret'})[2],
                          'Known invite cannot bypass missing CSRF')
                    check('Access Required' in request('/private/', {'invite_code': 'test-secret',
                          'invite_access_csrf': 'forged'})[2], 'Forged CSRF denied')
                    for path in ('//evil.test/', '/%2fevil.test/', '/%5cevil.test/', '/private/?x=1'):
                        status, headers, body = request(path, {'invite_code': 'wrong', 'invite_access_csrf': token})
                        check(status == 303, 'Invalid code PRG')
                        check(headers['Location'] == ('/private/' if path.startswith('/private/') else '/'),
                              'Redirect remains same-origin')
                    status, headers, body = request('/private/?secret=1', {
                        'invite_code': '123456' if sessions else 'test-secret', 'invite_access_csrf': token})
                    check(status == 303 and headers['Location'] == '/private/', 'Valid code PRG')
                    check(request('/private/')[2] == 'GATED CONTENT', 'Access persists on subsequent request')
                    if not sessions:
                        check('PHPSESSID' not in jar, 'Sessionless flow did not create PHP session')
                        jar['invite_access'] += 'tampered'
                        check('Access Required' in request('/private/')[2], 'Forged access cookie denied')
            finally:
                server.terminate()
                try:
                    server.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    server.kill()
                    server.wait(timeout=5)
            log.seek(0)
            output = log.read()
            check(not re.search(r'(Warning|Fatal error|Deprecated):', output), output)

print(f'PASS: {checks} HTTP checks (guest sessions enabled and disabled, config-file override)')
