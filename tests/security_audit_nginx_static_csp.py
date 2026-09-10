#!/usr/bin/env python3
"""Real loopback HTTP coverage for the opt-in Nginx snippets; fake data only."""
import argparse
import http.client
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
import shutil
import socket
import subprocess
import tempfile
import threading
import time


BASELINE = "script-src 'self' 'unsafe-inline' 'unsafe-eval'; object-src 'none'; base-uri 'self'; worker-src 'self' blob:;"
APP_POLICY = BASELINE.replace("'unsafe-eval';", "'unsafe-eval' https://approved.example.invalid;")


class ApplicationFixture(BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200)
        self.send_header('Content-Type', 'text/html; charset=utf-8')
        if self.path != '/upstream-no-csp':
            self.send_header('Content-Security-Policy', APP_POLICY)
        self.end_headers()
        self.wfile.write(b'APPLICATION_FIXTURE')

    def log_message(self, *args):
        pass


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--nginx', default=shutil.which('nginx'))
    args = parser.parse_args()
    if not args.nginx:
        parser.error('Nginx/OpenResty is required; supply --nginx /path/to/nginx')
    root = Path(__file__).resolve().parents[1]
    checks = 0

    def check(condition, message):
        nonlocal checks
        if not condition:
            raise AssertionError(message)
        checks += 1

    with tempfile.TemporaryDirectory(prefix='maccms-nginx-static-csp-') as temporary:
        directory = Path(temporary)
        directory.chmod(0o755)
        document_root = directory / 'html'
        for name in ['static/player/index.html', 'static/player/frame.htm', 'static/player/frame.HTML',
                     'static_new/ueditor/dialogs/preview/preview.html', '404.html']:
            target = document_root / name
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text('STATIC_HTML_FIXTURE')
        for name, body in [('static/app.js', 'SCRIPT_FIXTURE'), ('static/app.css', 'STYLE_FIXTURE'),
                           ('application/private.html', 'PRIVATE_FIXTURE'), ('upload/page.html', 'PRIVATE_FIXTURE'),
                           ('static/player/source.php.html', 'PRIVATE_FIXTURE'), ('static/player/source.bak.html', 'PRIVATE_FIXTURE')]:
            target = document_root / name
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text(body)
        upstream = ThreadingHTTPServer(('127.0.0.1', 0), ApplicationFixture)
        thread = threading.Thread(target=upstream.serve_forever, daemon=True)
        thread.start()
        with socket.socket() as reservation:
            reservation.bind(('127.0.0.1', 0))
            port = reservation.getsockname()[1]
        proxy = f'proxy_pass http://127.0.0.1:{upstream.server_port};'
        header_include = f'include "{root}/deploy/nginx/maccms-static-html-csp-header.conf";'
        configuration = directory / 'nginx.conf'
        configuration.write_text(f'''
daemon off;
master_process off;
pid "{directory}/nginx.pid";
error_log "{directory}/error.log" notice;
events {{ worker_connections 32; }}
http {{
    access_log off;
    types {{ text/html html htm; application/javascript js; text/css css; }}
    client_body_temp_path "{directory}/client_temp";
    proxy_temp_path "{directory}/proxy_temp";
    proxy_cache_path "{directory}/proxy_cache" keys_zone=fixture_cache:1m max_size=2m;
    include "{root}/deploy/nginx/maccms-static-html-csp-map.conf";
    server {{
        listen 127.0.0.1:{port};
        root "{document_root}";
        index index.html;
        add_header X-Content-Type-Options nosniff always;
        {header_include}
        location ~ ^/(application|upload)(/|$) {{ return 403; }}
        location = /cached.php {{
            {proxy}
            proxy_cache fixture_cache;
            proxy_cache_valid 200 1m;
            add_header X-Fixture-Cache $upstream_cache_status always;
            {header_include}
        }}
        location ~ ^/[^/]+[.]php(?:/|$) {{ {proxy} }}
        location ~* [.](php[0-9]*|bak)(?:[./]|$) {{ return 403; }}
        # A child with its own headers must include the CSP header itself.
        location /static_new/ueditor/ {{
            add_header X-Editor-Fixture local always;
            add_header X-Content-Type-Options nosniff always;
            {header_include}
            try_files $uri =404;
        }}
        location /static/ {{ try_files $uri $uri/ =404; }}
        location / {{ try_files $uri $uri/ @application; }}
        location @application {{ {proxy} }}
    }}
}}
''')
        process = None
        try:
            subprocess.run([args.nginx, '-t', '-p', str(directory), '-c', str(configuration)],
                           capture_output=True, text=True, check=True)
            process = subprocess.Popen([args.nginx, '-p', str(directory), '-c', str(configuration)],
                                       stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)

            def request(path, method='GET'):
                connection = http.client.HTTPConnection('127.0.0.1', port, timeout=3)
                try:
                    connection.request(method, path)
                    response = connection.getresponse()
                    body = response.read().decode()
                    policies = [value for name, value in response.getheaders() if name.lower() == 'content-security-policy']
                    return response.status, body, policies, dict(response.getheaders())
                finally:
                    connection.close()

            deadline = time.monotonic() + 5
            while True:
                try:
                    request('/404.html')
                    break
                except (OSError, http.client.HTTPException):
                    if process.poll() is not None or time.monotonic() >= deadline:
                        raise RuntimeError('Isolated Nginx failed to start: ' + (directory / 'error.log').read_text())
                    time.sleep(0.05)
            for path in ['/static/player/index.html', '/static/player/', '/static/player/frame.htm',
                         '/static/player/frame.HTML', '/static_new/ueditor/dialogs/preview/preview.html', '/404.html']:
                status, body, policies, headers = request(path + '?v=fixture')
                check(status == 200 and body == 'STATIC_HTML_FIXTURE', 'Static HTML remains readable: ' + path)
                check(policies == [BASELINE], 'One enforced static policy: ' + path)
                check(headers.get('X-Content-Type-Options') == 'nosniff', 'Other security headers remain: ' + path)
            check(request('/static_new/ueditor/dialogs/preview/preview.html')[3].get('X-Editor-Fixture') == 'local',
                  'Child location headers coexist with CSP')
            status, body, policies, _ = request('/static/player/index.html', 'HEAD')
            check(status == 200 and body == '' and policies == [BASELINE], 'HEAD includes CSP')
            for path in ['/index.php/vod/play.html', '/vod/play.html', '/upstream/player.html']:
                status, body, policies, _ = request(path)
                check(status == 200 and body == 'APPLICATION_FIXTURE' and policies == [APP_POLICY],
                      'Upstream approved origins survive direct and rewritten routes: ' + path)
            check(request('/upstream-no-csp')[2] == [], 'An upstream without CSP requires its own fix')
            for expected_cache_status in ['MISS', 'HIT']:
                status, body, policies, headers = request('/cached.php')
                check(status == 200 and headers.get('X-Fixture-Cache') == expected_cache_status,
                      'Exercise an actual upstream cache ' + expected_cache_status)
                check(policies == [APP_POLICY], 'Cached upstream approved origins remain unchanged: ' + expected_cache_status)
            for path in ['/static/app.js', '/static/app.css']:
                check(request(path)[0] == 200 and request(path)[2] == [], 'Non-HTML response has no added CSP: ' + path)
            for path in ['/application/private.html', '/upload/page.html', '/static/player/source.php.html', '/static/player/source.bak.html']:
                status, body, policies, _ = request(path)
                check(status == 403 and 'PRIVATE_FIXTURE' not in body, 'Existing deny precedences remain: ' + path)
                check(policies == [BASELINE], 'Locally generated HTML denial also carries CSP: ' + path)
            status, body, policies, _ = request('/static/missing.html')
            check(status == 404 and policies == [BASELINE], 'Static HTML error response has enforced CSP')
            print(f'OK {checks} Nginx static HTML CSP boundary checks')
        finally:
            if process is not None:
                process.terminate()
                try:
                    process.communicate(timeout=5)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.communicate(timeout=5)
            upstream.shutdown()
            upstream.server_close()
            thread.join(timeout=2)


if __name__ == '__main__':
    main()
