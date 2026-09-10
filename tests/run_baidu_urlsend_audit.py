#!/usr/bin/env python3
"""Real HTTPS fixtures on Unix sockets; no public network access and no actual Baidu submissions."""
import http.server
import json
from pathlib import Path
import socketserver
import ssl
import subprocess
import sys
import tempfile
import threading
import time


class Server(socketserver.ThreadingMixIn, socketserver.UnixStreamServer):
    daemon_threads = True

    def get_request(self):
        connection, address = super().get_request()
        try:
            return self.context.wrap_socket(connection, server_side=True), address
        except Exception:
            connection.close()
            raise

    def handle_error(self, request, client_address):
        pass  # Expected TLS disconnects/timeouts are asserted by the PHP test.


class Handler(http.server.BaseHTTPRequestHandler):
    def log_message(self, *args):
        pass

    def do_POST(self):
        body = self.rfile.read(int(self.headers.get("Content-Length", "0")))
        with self.server.lock:
            with (self.server.directory / "requests.jsonl").open("a") as log:
                log.write(json.dumps({"method": "POST", "path": self.path, "headers": dict(self.headers),
                                      "body": body.decode("utf-8")}) + "\n")
            response = json.loads((self.server.directory / "response.json").read_text())
        if response.get("disconnect"):
            return
        time.sleep(response.get("delay", 0))
        response_body = response.get("body", "").encode("utf-8")
        self.send_response(response.get("status", 200))
        self.send_header("Content-Type", "application/json")
        for key, value in response.get("headers", {}).items():
            self.send_header(key, value)
        self.send_header("Content-Length", str(len(response_body)))
        self.end_headers()
        try:
            self.wfile.write(response_body)
        except (BrokenPipeError, ConnectionResetError, ssl.SSLError):
            pass


def main():
    root = Path(__file__).resolve().parents[1]
    images = sys.argv[1:] or ["maccms10-migration-check:latest", "maccms-audit-php84:20260910"]
    with tempfile.TemporaryDirectory(prefix="maccms-baidu-urlsend-") as temporary:
        directory = Path(temporary)
        def openssl(*args):
            subprocess.run(["openssl", *args], cwd=directory, check=True,
                           stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
        openssl("req", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout", "ca.key", "-out", "ca.pem",
                "-days", "1", "-subj", "/CN=Disposable Baidu audit CA")
        servers = []
        for label, host in [("valid", "data.zz.baidu.com"), ("wrong-host", "wrong.example.invalid")]:
            openssl("req", "-newkey", "rsa:2048", "-nodes", "-keyout", label + ".key", "-out", label + ".csr",
                    "-subj", "/CN=" + host)
            (directory / (label + ".ext")).write_text("subjectAltName=DNS:" + host + "\nextendedKeyUsage=serverAuth\n")
            openssl("x509", "-req", "-in", label + ".csr", "-CA", "ca.pem", "-CAkey", "ca.key", "-CAcreateserial",
                    "-out", label + ".pem", "-days", "1", "-extfile", label + ".ext")
            server = Server(str(directory / (label + ".sock")), Handler)
            server.directory = directory
            server.lock = threading.Lock()
            server.context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            server.context.load_cert_chain(directory / (label + ".pem"), directory / (label + ".key"))
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()
            servers.append((server, thread))
        try:
            (directory / "requests.jsonl").touch()
            (directory / "response.json").write_text('{}')
            for image in images:
                subprocess.run([
                    "docker", "run", "--rm", "--network", "none", "-e", "BAIDU_AUDIT_SOCKET_FIXTURE=1",
                    "-v", str(root) + ":/app:ro", "-v", str(directory) + ":/audit", "-w", "/tmp",
                    "--entrypoint", "php", image, "/app/tests/extensions_audit_baidu_urlsend.php",
                ], check=True, timeout=120)
        finally:
            for server, thread in servers:
                server.shutdown()
                server.server_close()
                thread.join(timeout=5)


if __name__ == "__main__":
    main()
