#!/usr/bin/env python3
"""Foreground localhost proxy into the demo's network namespace (standard library)."""
import http.server
import subprocess
import sys

FETCH = """
import sys, urllib.request
with urllib.request.urlopen('http://127.0.0.1:8088' + sys.argv[1], timeout=2) as response:
    sys.stdout.buffer.write(response.read())
"""


class Handler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        # Fixed local dashboard assets/endpoints only; no arbitrary URLs/paths.
        types = {"/": "text/html; charset=utf-8", "/app.js": "text/javascript; charset=utf-8",
                 "/app.css": "text/css; charset=utf-8", "/stats.json": "application/json",
                 "/jail.json": "application/json", "/log.json": "application/json",
                 "/health.json": "application/json"}
        if self.path not in types:
            self.send_error(404)
            return
        try:
            result = subprocess.run(
                ["nsenter", "--net=" + sys.argv[1], "python3", "-c", FETCH, self.path],
                capture_output=True, timeout=3, check=True,
            )
        except (OSError, subprocess.SubprocessError):
            self.send_error(503, "Demo unavailable; start it with sudo ./demo.sh start")
            return
        self.send_response(200)
        self.send_header("Content-Type", types[self.path])
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Content-Security-Policy", "default-src 'self'; style-src 'self'; script-src 'self'; frame-ancestors 'none'; base-uri 'none'")
        self.send_header("Cache-Control", "no-store")
        self.send_header("Content-Length", str(len(result.stdout)))
        self.end_headers()
        try:
            self.wfile.write(result.stdout)
        except (BrokenPipeError, ConnectionResetError):
            pass


if __name__ == "__main__":
    try:
        server = http.server.ThreadingHTTPServer(("127.0.0.1", 8088), Handler)
    except OSError as error:
        sys.exit(f"Cannot open dashboard proxy on 127.0.0.1:8088: {error}")
    print("Dashboard: http://127.0.0.1:8088/ — Ctrl+C stops the proxy, not the demo.", flush=True)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
