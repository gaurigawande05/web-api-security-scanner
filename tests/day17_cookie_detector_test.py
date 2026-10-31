from http.server import BaseHTTPRequestHandler, HTTPServer
from threading import Thread
import requests

from scanner.cookies import check_cookies


class CookieTestHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200)

        # Cookie 1: Missing all three security attributes
        self.send_header(
            "Set-Cookie",
            "insecure_session=abc123; Path=/"
        )

        # Cookie 2: Has all three security attributes
        self.send_header(
            "Set-Cookie",
            "secure_session=xyz789; Path=/; Secure; HttpOnly; SameSite=Lax"
        )

        # Cookie 3: Missing HttpOnly and SameSite
        self.send_header(
            "Set-Cookie",
            "test_cookie=value123; Path=/; Secure"
        )

        self.end_headers()
        self.wfile.write(b"Cookie security detector test")

    def log_message(self, format, *args):
        pass


server = HTTPServer(("127.0.0.1", 8767), CookieTestHandler)
thread = Thread(target=server.serve_forever, daemon=True)
thread.start()

try:
    print("Cookie detector test started.")

    response = requests.get(
        "http://127.0.0.1:8767",
        timeout=5
    )

    findings = check_cookies(response)

    print("\nTotal findings:", len(findings))
    print("\nDetected findings:")

    for finding in findings:
        print(
            f"- {finding['name']} | "
            f"Severity: {finding['severity']}"
        )

    expected = {
        "Cookie 'insecure_session' Missing Secure Attribute",
        "Cookie 'insecure_session' Missing HttpOnly Attribute",
        "Cookie 'insecure_session' Missing SameSite Attribute",
        "Cookie 'test_cookie' Missing HttpOnly Attribute",
        "Cookie 'test_cookie' Missing SameSite Attribute",
    }

    actual = {finding["name"] for finding in findings}

    print("\nExpected findings:", len(expected))
    print("Actual unique findings:", len(actual))

    if actual == expected and len(findings) == len(expected):
        print("PASS: Cookie security detection matched all expected results.")
    else:
        print("CHECK: Actual findings differ from expected findings.")
        print("Missing findings:", sorted(expected - actual))
        print("Unexpected findings:", sorted(actual - expected))

finally:
    server.shutdown()
    server.server_close()
    print("\nCookie detector test server stopped.")
