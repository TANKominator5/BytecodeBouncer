#!/usr/bin/env python3
"""Foreground localhost proxy into the demo's network namespace (standard library).

Static dashboard files are read from the repo so frontend edits appear on
refresh without rebuilding the daemon. Only live JSON comes from the namespace.
"""
import http.server
import subprocess
import sys
from pathlib import Path

HOST = "127.0.0.1"
PORT = 8088
FETCH = f"""
import sys, urllib.request
with urllib.request.urlopen('http://{HOST}:{PORT}' + sys.argv[1], timeout=2) as response:
    sys.stdout.buffer.write(response.read())
"""

WEB = Path(__file__).resolve().parents[2] / "internal" / "observe" / "web"
STATIC = {
    "/": (WEB / "index.html", "text/html; charset=utf-8"),
    "/app.js": (WEB / "app.js", "text/javascript; charset=utf-8"),
    "/app.css": (WEB / "app.css", "text/css; charset=utf-8"),
    "/fonts/monocraft-regular.ttf": (WEB / "fonts" / "monocraft-regular.ttf", "font/ttf"),
    "/fonts/monocraft-bold.ttf": (WEB / "fonts" / "monocraft-bold.ttf", "font/ttf"),
}
LIVE_PATHS = {"/stats.json", "/jail.json", "/log.json", "/health.json"}


class Handler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path in STATIC:
            path, content_type = STATIC[self.path]
            try:
                body = path.read_bytes()
            except OSError:
                self.send_error(503, "Dashboard asset missing from repo")
                return
            self.respond(content_type, body)
            return
        # Fixed live endpoints only; no arbitrary URLs/paths or static paths.
        if self.path not in LIVE_PATHS:
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
        self.respond("application/json", result.stdout)

    def respond(self, content_type, body):
        self.send_response(200)
        self.send_header("Content-Type", content_type)
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Content-Security-Policy", "default-src 'self'; style-src 'self'; script-src 'self'; frame-ancestors 'none'; base-uri 'none'")
        self.send_header("Cache-Control", "no-store")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        try:
            self.wfile.write(body)
        except (BrokenPipeError, ConnectionResetError):
            pass


def main():
    if len(sys.argv) != 2:
        sys.exit("usage: dashboard_proxy.py <network-namespace>")
    try:
        server = http.server.ThreadingHTTPServer((HOST, PORT), Handler)
    except OSError as error:
        sys.exit(f"Cannot open dashboard proxy on {HOST}:{PORT}: {error}")
    print(f"Dashboard: http://{HOST}:{PORT}/ — Ctrl+C stops the proxy, not the demo.", flush=True)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()


if __name__ == "__main__":
    main()
