#!/usr/bin/env python3
"""
Packager script for TRUST Security Suite ZIP deliverable.
"""

import os
import zipfile

def generate_zip():
    archive_name = "trust-security-suite.zip"
    base_dir = os.path.dirname(os.path.abspath(__file__))
    output_path = os.path.join(base_dir, archive_name)

    files_to_include = [
        "index.html",
        "trust-standalone.html",
        "server.py",
        "bundle_standalone.py",
        "generate_zip.py",
        "README.md",
        "static/css/main.css",
        "static/css/components.css",
        "static/css/print.css",
        "static/css/terminal.css",
        "static/js/app.js",
        "static/js/biometricSandbox.js",
        "static/js/i18n.js",
        "static/js/qrcode.js",
        "static/js/reportExporter.js",
        "static/js/scoring.js",
        "static/js/simulator.js",
        "static/js/terminalI18n.js",
        "static/js/staticPageI18n.js",
        "static/js/detectors/browserEnv.js",
        "static/js/detectors/canvasWebgl.js",
        "static/js/detectors/clipboard.js",
        "static/js/detectors/domScript.js",
        "static/js/detectors/environment.js",
        "static/js/detectors/inputTiming.js",
        "static/js/detectors/networkSignals.js",
        "tests/run_tests.sh",
        "tests/test_detectors.js",
        "tests/test_scoring.py",
        "docs/API_REFERENCE.md",
        "docs/ARCHITECTURE.md",
        "docs/DEPLOYMENT_GUIDE.md",
        "docs/KNOWN_LIMITATIONS.md"
    ]

    print(f"Creating {archive_name}...")
    with zipfile.ZipFile(output_path, "w", zipfile.ZIP_DEFLATED) as zipf:
        for rel_path in files_to_include:
            full_path = os.path.join(base_dir, rel_path)
            if os.path.exists(full_path):
                zipf.write(full_path, arcname=rel_path)
                print(f"  + Added: {rel_path}")
            else:
                print(f"  ! Warning: {rel_path} not found")

    print(f"Successfully generated {output_path} ({os.path.getsize(output_path)} bytes)")

if __name__ == "__main__":
    generate_zip()
