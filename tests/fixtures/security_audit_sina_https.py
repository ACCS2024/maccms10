"""Loopback-only TLS fixture for the legacy client. Never contacts a provider."""
import http.server
import json
import pathlib
import ssl
import subprocess
import sys
import threading
import signal

root = pathlib.Path(sys.argv[1])

def openssl(*args):
    subprocess.run(['openssl', *args], cwd=root, check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

openssl('req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-days', '1', '-subj', '/CN=Audit fixture CA', '-keyout', 'ca.key', '-out', 'ca.crt')
for name, sans in [('good', 'DNS:login.sina.com.cn,DNS:picupload.service.weibo.com'), ('wrong', 'DNS:wrong.invalid')]:
    openssl('req', '-newkey', 'rsa:2048', '-nodes', '-subj', '/CN=Audit fixture', '-keyout', name+'.key', '-out', name+'.csr')
    (root/(name+'.ext')).write_text('subjectAltName='+sans+'\nextendedKeyUsage=serverAuth\n')
    openssl('x509', '-req', '-in', name+'.csr', '-CA', 'ca.crt', '-CAkey', 'ca.key', '-CAcreateserial', '-days', '1', '-extfile', name+'.ext', '-out', name+'.crt')

class Handler(http.server.BaseHTTPRequestHandler):
    def log_message(self, *args):
        pass
    def do_POST(self):
        body = self.rfile.read(int(self.headers.get('Content-Length', '0')))
        with (root/'received.jsonl').open('a') as out:
            out.write(json.dumps({'path': self.path, 'cookie': self.headers.get('Cookie', ''), 'body': body.decode('latin1')})+'\n')
        state = json.loads((root/'response.json').read_text())
        self.send_response(state.get('status', 200))
        if state.get('cookie'):
            self.send_header('sEt-CoOkIe', state['cookie'])
        if state.get('redirect'):
            self.send_header('Location', state['redirect'])
        self.send_header('Content-Length', str(len(state.get('body', '').encode())))
        self.end_headers()
        try:
            self.wfile.write(state.get('body', '').encode())
        except (BrokenPipeError, ssl.SSLError):
            pass

ports = {}
for name in ['good', 'wrong']:
    server = http.server.ThreadingHTTPServer(('127.0.0.1', 0), Handler)
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(root/(name+'.crt'), root/(name+'.key'))
    server.socket = context.wrap_socket(server.socket, server_side=True)
    ports[name] = server.server_port
    threading.Thread(target=server.serve_forever, daemon=True).start()
(root/'ports.json').write_text(json.dumps(ports))
signal.pause()
