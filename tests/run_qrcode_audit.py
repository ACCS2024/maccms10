#!/usr/bin/env python3
"""Generate QR fixtures in isolated PHP containers and decode with independent ZXing-C++."""
import json
from pathlib import Path
import subprocess
import sys
import tempfile

import cv2
import zxingcpp


def main():
    root = Path(__file__).resolve().parents[1]
    arguments = sys.argv[1:]
    http_only = "--http-only" in arguments
    images = [argument for argument in arguments if argument != "--http-only"] or [
        "maccms10-migration-check:latest", "maccms-audit-php84:20260910"]
    suites = ["extensions_audit_qrcode_http.php"] if http_only else [
        "extensions_audit_qrcode.php", "extensions_audit_qrcode_http.php"]
    with tempfile.TemporaryDirectory(prefix="maccms-qrcode-") as temporary:
        for index, image in enumerate(images):
            for suite_index, suite in enumerate(suites):
                directory = "run" + str(index) + "-" + str(suite_index)
                subprocess.run([
                    "docker", "run", "--rm", "--network", "none", "-v", str(root) + ":/app:ro",
                    "-v", temporary + ":/audit", "-e", "QRCODE_AUDIT_OUTPUT=/audit/" + directory,
                    "-w", "/audit", "--entrypoint", "php", image, "/app/tests/" + suite,
                ], check=True, timeout=120)
                output = Path(temporary) / directory
                manifest = json.loads((output / "manifest.json").read_text())
                for case in manifest["images"]:
                    pixels = cv2.imread(str(output / case["file"]))
                    # Check both decoded text and bytes, including the legacy library's Shift-JIS Kanji mode.
                    expected = case["text"].encode(case.get("encoding", "utf-8"))
                    decoded = zxingcpp.read_barcode(pixels)
                    if decoded is None or not decoded.valid or decoded.bytes != expected or decoded.text != case["text"]:
                        raise AssertionError("ZXing-C++ payload mismatch: " + case["file"])
                print("OK", len(manifest["images"]), "independent ZXing-C++ decodes for PHP", manifest["php"], flush=True)


if __name__ == "__main__":
    main()
