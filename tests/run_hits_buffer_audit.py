#!/usr/bin/env python3
"""Run HitsBuffer regressions against disposable MySQL and Redis Unix sockets."""
import os
from pathlib import Path
import secrets
import shutil
import subprocess
import sys
import tempfile
import time


def main():
    root = Path(__file__).resolve().parents[1]
    images = sys.argv[1:] or ["maccms10-migration-check:latest", "maccms-audit-php84:20260910"]
    redis_binary = shutil.which("redis-server")
    if not redis_binary:
        raise RuntimeError("redis-server is required for this isolated fixture")
    for image in ["mysql:8.0", *images]:
        subprocess.run(["docker", "image", "inspect", image], check=True, stdout=subprocess.DEVNULL)
    token = secrets.token_hex(6)
    name = "maccms-audit-hits-" + token
    password = secrets.token_hex(24)
    database = "maccms_audit_hits_" + token
    with tempfile.TemporaryDirectory(prefix="maccms-hits-") as temporary:
        temporary = Path(temporary)
        sockets = temporary / "sockets"
        sockets.mkdir(mode=0o777)
        sockets.chmod(0o777)  # The MySQL container uses its own unprivileged UID.
        env_file = temporary / "fixture.env"
        env_file.write_text("\n".join([
            "HITS_AUDIT_MYSQL_SOCKET=/audit/mysql.sock",
            "HITS_AUDIT_REDIS_SOCKET=/audit/redis.sock",
            "HITS_AUDIT_DATABASE=" + database,
            "HITS_AUDIT_PASSWORD=" + password,
            "HITS_AUDIT_PREFIX=audit_hits_" + token + ":",
        ]) + "\n")
        env_file.chmod(0o600)
        redis_log = (temporary / "redis.log").open("w")
        redis = subprocess.Popen([
            redis_binary, "--port", "0", "--unixsocket", str(sockets / "redis.sock"),
            "--unixsocketperm", "777", "--save", "", "--appendonly", "no",
        ], stdout=redis_log, stderr=subprocess.STDOUT, cwd=temporary)
        started = False
        try:
            environment = dict(os.environ, MYSQL_ROOT_PASSWORD=password, MYSQL_DATABASE=database)
            subprocess.run([
                "docker", "run", "--rm", "-d", "--network", "none", "--name", name,
                "-e", "MYSQL_ROOT_PASSWORD", "-e", "MYSQL_DATABASE",
                "-v", str(sockets) + ":/audit", "mysql:8.0",
                "--socket=/audit/mysql.sock", "--skip-networking",
            ], env=environment, check=True, stdout=subprocess.DEVNULL)
            started = True
            deadline = time.monotonic() + 90
            while time.monotonic() < deadline:
                probe = subprocess.run([
                    "docker", "exec", name, "sh", "-c",
                    'test "$(cat /proc/1/comm)" = mysqld && '
                    'MYSQL_PWD="$MYSQL_ROOT_PASSWORD" exec mysql -uroot --socket=/audit/mysql.sock '
                    '-Nse "SELECT SCHEMA_NAME FROM information_schema.SCHEMATA WHERE SCHEMA_NAME = \'$MYSQL_DATABASE\'"',
                ], capture_output=True, text=True)
                if probe.returncode == 0 and database in probe.stdout and (sockets / "redis.sock").exists():
                    break
                time.sleep(0.2)
            else:
                raise RuntimeError("Disposable MySQL/Redis fixture did not become ready")
            for image in images:
                subprocess.run([
                    "docker", "run", "--rm", "--network", "none", "--env-file", str(env_file),
                    "-v", str(root) + ":/app:ro", "-v", str(sockets) + ":/audit",
                    "-w", "/tmp", "--entrypoint", "php", image,
                    "/app/tests/extensions_audit_hits_buffer.php",
                ], check=True, timeout=120)
        finally:
            if started:
                subprocess.run(["docker", "stop", "-t", "5", name], stdout=subprocess.DEVNULL, check=False)
            redis.terminate()
            redis.wait(timeout=10)
            redis_log.close()


if __name__ == "__main__":
    main()
