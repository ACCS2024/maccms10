#!/usr/bin/env python3
"""Cloud SDK redirect tests: real HTTP/TLS on a local Unix socket, no external network."""
import http.server
import json
from pathlib import Path
import socket
import socketserver
import ssl
import subprocess
import sys
import tempfile
import threading


class Server(socketserver.ThreadingMixIn, socketserver.UnixStreamServer):
    daemon_threads = True

    def get_request(self):
        connection, address = super().get_request()
        try:
            if connection.recv(1, socket.MSG_PEEK) == b"\x16":
                connection = self.context.wrap_socket(connection, server_side=True)
            return connection, address
        except Exception:
            connection.close()
            raise

    def handle_error(self, request, address):
        pass  # TLS-negative fixtures intentionally disconnect during handshake.


class Handler(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, *args):
        pass

    def serve(self):
        body = self.rfile.read(int(self.headers.get("Content-Length", "0")))
        with self.server.lock:
            with (self.server.directory / "requests.jsonl").open("a") as log:
                log.write(json.dumps({"method": self.command, "host": self.headers.get("Host"), "path": self.path,
                                      "tls": isinstance(self.connection, ssl.SSLSocket),
                                      "body": body.decode("utf-8"), "authorized": bool(self.headers.get("Authorization"))}) + "\n")
            response = json.loads((self.server.directory / "response.json").read_text())
        status = 200 if self.headers.get("Host") == "collector.invalid" else response.get("status", 200)
        payload = json.dumps({"key": "fixture-key", "tasks": [], "invalid_domain_of_url": []}).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("X-Upyun-Width", "10")
        self.send_header("Content-Length", str(len(payload)))
        self.send_header("Connection", "close")
        if status in range(300, 400):
            self.send_header("Location", response["location"])
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(payload)

    do_GET = do_POST = do_PUT = do_HEAD = do_DELETE = serve


def main():
    root = Path(__file__).resolve().parents[1]
    baseline = "--baseline" in sys.argv
    images = [arg for arg in sys.argv[1:] if arg != "--baseline"] or ["maccms10-migration-check:latest", "maccms-audit-php84:20260910"]
    with tempfile.TemporaryDirectory(prefix="maccms-sdk-redirect-") as temporary:
        directory = Path(temporary)

        def openssl(*args):
            subprocess.run(["openssl", *args], cwd=directory, check=True, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)

        for label in ["ca", "untrusted"]:
            openssl("req", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout", label + ".key", "-out", label + ".pem",
                    "-days", "1", "-subj", "/CN=Disposable SDK audit " + label)
        openssl("req", "-newkey", "rsa:2048", "-nodes", "-keyout", "server.key", "-out", "server.csr", "-subj", "/CN=upload.invalid")
        hosts = ["upload.invalid", "collector.invalid", "v0.api.upyun.com", "p0.api.upyun.com", "p1.api.upyun.com", "purge.upyun.com"]
        (directory / "server.ext").write_text("subjectAltName=" + ",".join("DNS:" + host for host in hosts) + "\nextendedKeyUsage=serverAuth\n")
        openssl("x509", "-req", "-in", "server.csr", "-CA", "ca.pem", "-CAkey", "ca.key", "-CAcreateserial",
                "-out", "server.pem", "-days", "1", "-extfile", "server.ext")
        server = Server(str(directory / "server.sock"), Handler)
        server.context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        server.context.load_cert_chain(directory / "server.pem", directory / "server.key")
        server.directory = directory
        server.lock = threading.Lock()
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        (directory / "requests.jsonl").touch()
        (directory / "response.json").write_text('{}')
        try:
            for image in images:
                subprocess.run(["docker", "run", "--rm", "--network", "none", "-v", str(root) + ":/app:ro",
                                "-v", str(directory) + ":/audit", "-w", "/tmp", "--entrypoint", "php", image,
                                "/app/tests/extensions_audit_sdk_redirects.php", *(["baseline"] if baseline else [])],
                               check=True, timeout=120)
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=5)


if __name__ == "__main__":
    main()
