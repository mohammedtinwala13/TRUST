#!/usr/bin/env python3
"""
Bundle TRUST modular components into a single standalone, zero-dependency HTML file.
"""

import os

def bundle_standalone():
    with open('index.html', 'r', encoding='utf-8') as f:
        html = f.read()

    # Read CSS files
    with open('static/css/main.css', 'r', encoding='utf-8') as f:
        main_css = f.read()
    with open('static/css/components.css', 'r', encoding='utf-8') as f:
        comp_css = f.read()
    with open('static/css/print.css', 'r', encoding='utf-8') as f:
        print_css = f.read()

    combined_css = f"<style>\n{main_css}\n{comp_css}\n{print_css}\n</style>"

    # Read JS files
    js_files = [
        'static/js/i18n.js',
        'static/js/qrcode.js',
        'static/js/detectors/inputTiming.js',
        'static/js/detectors/clipboard.js',
        'static/js/detectors/domScript.js',
        'static/js/detectors/browserEnv.js',
        'static/js/detectors/canvasWebgl.js',
        'static/js/detectors/networkSignals.js',
        'static/js/detectors/environment.js',
        'static/js/scoring.js',
        'static/js/simulator.js',
        'static/js/biometricSandbox.js',
        'static/js/reportExporter.js',
        'static/js/app.js'
    ]

    combined_js = "<script>\n"
    for js_path in js_files:
        with open(js_path, 'r', encoding='utf-8') as f:
            combined_js += f"\n/* --- {js_path} --- */\n" + f.read() + "\n"
    combined_js += "</script>"

    # Replace <link rel="stylesheet" ... /> with inline styles
    import re
    html = re.sub(r'<link\s+rel="stylesheet"\s+href="static/css/[^"]+"\s*/>\s*', '', html)
    html = html.replace('</head>', f'{combined_css}\n</head>')

    # Replace <script src="static/js/..."></script> with inline scripts
    html = re.sub(r'<script\s+src="static/js/[^"]+"></script>\s*', '', html)
    html = html.replace('</body>', f'{combined_js}\n</body>')

    with open('trust-standalone.html', 'w', encoding='utf-8') as f:
        f.write(html)

    print("Successfully built trust-standalone.html (Size: {} bytes)".format(os.path.getsize('trust-standalone.html')))

if __name__ == '__main__':
    bundle_standalone()
