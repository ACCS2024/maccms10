#!/usr/bin/env python3
"""Exercise only DataConfig with ordinary temporary data; no loader or site bootstrap."""
from pathlib import Path
import subprocess
import sys


def main():
    root = Path(__file__).resolve().parents[1]
    images = sys.argv[1:] or ["maccms10-migration-check:latest", "maccms-audit-php84:20260910"]
    scenarios = ["compatibility", "literal_edges", "syntax_rejections", "dense_array", "normal_configuration", "dense_rejection",
                 "large_string", "mixed", "escaped_string", "comments", "lexical_rejections", "read"]
    for image in images:
        subprocess.run(["docker", "image", "inspect", image], check=True, stdout=subprocess.DEVNULL)
        for scenario in scenarios:
            subprocess.run([
                "docker", "run", "--rm", "--network", "none", "-v", str(root) + ":/app:ro",
                "--entrypoint", "php", image, "-n", "-d", "memory_limit=128M", "-d", "error_reporting=-1",
                "/app/tests/data_config_parser_audit.php", scenario,
            ], check=True, timeout=30)


if __name__ == "__main__":
    main()
