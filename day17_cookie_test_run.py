from http.server import BaseHTTPRequestHandler, HTTPServer
from threading import Thread
import requests

class CookieTestHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200)

        self.send_header(
            "Set-Cookie",
            "insecure_session=abc123; Path=/"
        )

        self.send_header(
            "Set-Cookie",
            "secure_session=xyz789; Path=/; Secure; HttpOnly; SameSite=Lax"
        )

        self.send_header(
            "Set-Cookie",
            "test_cookie=value123; Path=/; Secure"
        )

        self.end_headers()
        self.wfile.write(b"Cookie security test server")

    def log_message(self, format, *args):
        pass

server = HTTPServer(("127.0.0.1", 8766), CookieTestHandler)
thread = Thread(target=server.serve_forever, daemon=True)
thread.start()

try:
    print("Cookie test server started.")

    response = requests.get(
        "http://127.0.0.1:8766",
        timeout=5
    )

    print("HTTP Status:", response.status_code)

    raw_headers = getattr(response.raw, "headers", None)

    if raw_headers is not None and hasattr(raw_headers, "getlist"):
        cookie_headers = raw_headers.getlist("Set-Cookie")
    else:
        cookie_headers = []

    print("\nSet-Cookie headers received:")

    for cookie in cookie_headers:
        print("-", cookie)

    print("\nTotal separate Set-Cookie headers:", len(cookie_headers))

    if len(cookie_headers) == 3:
        print("PASS: All three separate cookie headers were received.")
    else:
        print("CHECK: Expected three separate cookie headers.")

finally:
    server.shutdown()
    server.server_close()
    print("\nCookie test server stopped.")
