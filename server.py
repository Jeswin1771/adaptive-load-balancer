"""TCP application server: python3 server.py <name> [port]
Replies with 'served by <name>' followed by padding so network load is measurable."""
import sys
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

NAME = sys.argv[1] if len(sys.argv) > 1 else "server"
PORT = int(sys.argv[2]) if len(sys.argv) > 2 else 80
PAD = 100_000  # bytes of padding per response


class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        time.sleep(0.3)  # simulate work so requests overlap (concurrency)
        body = ("served by %s\n" % NAME).encode() + b"x" * PAD
        self.send_response(200)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args):
        pass


ThreadingHTTPServer(("0.0.0.0", PORT), Handler).serve_forever()
