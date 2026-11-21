import http.server
import json
import sys


class Handler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path == "/api/tags":
            body = json.dumps(
                {"models": [{"name": "llama3.1:8b"}, {"name": "qwen2.5-coder:32b"}]}
            ).encode()
        elif self.path == "/api/version":
            body = json.dumps({"version": "0.5.0-demo"}).encode()
        else:
            self.send_response(404)
            self.end_headers()
            return
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args):
        pass


if __name__ == "__main__":
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 11434
    # Bound to all interfaces so enki reports it as network-exposed.
    http.server.HTTPServer(("0.0.0.0", port), Handler).serve_forever()
