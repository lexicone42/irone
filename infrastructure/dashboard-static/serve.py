#!/usr/bin/env python3
"""Local development server for the health dashboard.

Serves the dashboard on 0.0.0.0:8080 for testing from any device on the network.

Usage:
    python serve.py              # Serves on port 8080
    python serve.py 3000         # Serves on port 3000

Note: OAuth callbacks won't work locally unless you add the local URL
to Cognito's allowed callback URLs. For UI testing, the page will load
but auth flows will redirect to production.
"""

import http.server
import os
import socketserver
import sys
from pathlib import Path

PORT = int(sys.argv[1]) if len(sys.argv) > 1 else 8080
DIRECTORY = Path(__file__).resolve().parent


class Handler(http.server.SimpleHTTPRequestHandler):
    """Handler that serves index.html for SPA routing."""

    def __init__(self, *args, **kwargs):
        super().__init__(*args, directory=str(DIRECTORY), **kwargs)

    def do_GET(self):
        # SPA routing: serve index.html for all paths except static files
        if not (DIRECTORY / self.path.lstrip("/")).exists():
            self.path = "/index.html"
        return super().do_GET()

    def end_headers(self):
        # Add CORS headers for local development
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Cache-Control", "no-cache, no-store, must-revalidate")
        super().end_headers()


if __name__ == "__main__":
    with socketserver.TCPServer(("0.0.0.0", PORT), Handler) as httpd:
        local_ip = os.popen("hostname -I 2>/dev/null || echo 'localhost'").read().strip().split()[0]
        print("\n  Dashboard running at:")
        print(f"    Local:   http://localhost:{PORT}")
        print(f"    Network: http://{local_ip}:{PORT}")
        print("\n  Press Ctrl+C to stop\n")
        try:
            httpd.serve_forever()
        except KeyboardInterrupt:
            print("\n  Server stopped.")
