#!/usr/bin/env python3
"""TLS-сервер для tests/httpsmatch.sh: python ssl, TLS 1.3, ALPN http/1.1. Печатает порт первой строкой."""
import http.server, ssl, sys

class H(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    def log_message(self, *a): pass
    def send(self, code, body=b"", hdrs=()):
        self.send_response(code)
        for k, v in hdrs: self.send_header(k, v)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Connection", "close")
        self.end_headers()
        if self.command != "HEAD": self.wfile.write(body)
        self.close_connection = True
    def do_GET(self):
        p = self.path
        if p == "/ok": self.send(200, b"hello over tls")
        elif p == "/big": self.send(200, bytes((i * 7) & 0xff for i in range(5 * 1024 * 1024)))
        elif p == "/redir": self.send(302, hdrs=[("Location", "/ok")])
        elif p == "/downgrade": self.send(302, hdrs=[("Location", "http://localhost:1/ok")])
        elif p == "/etag":
            if self.headers.get("If-None-Match") == '"t1"': self.send(304, hdrs=[("ETag", '"t1"')])
            else: self.send(200, b"tagged", hdrs=[("ETag", '"t1"')])
        else: self.send(404)
    do_HEAD = do_GET

ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
ctx.minimum_version = ssl.TLSVersion.TLSv1_3
ctx.load_cert_chain(sys.argv[1], sys.argv[2])
ctx.set_alpn_protocols(["http/1.1"])
srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), H)
srv.socket = ctx.wrap_socket(srv.socket, server_side=True)
print(srv.server_address[1], flush=True)
srv.serve_forever()
