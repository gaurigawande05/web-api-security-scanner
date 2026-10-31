import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from unittest.mock import patch

from scanner.http_scanner import scan_target


# --------------------------------------------------
# Local test server
# --------------------------------------------------

class TestHandler(BaseHTTPRequestHandler):

    def do_GET(self):
        self.send_response(200)

        # Deliberately provide an invalid header value
        self.send_header("X-Content-Type-Options", "invalid-value")

        # Deliberately provide an insecure cookie
        self.send_header(
            "Set-Cookie",
            "test_session=abc123"
        )

        self.send_header("Content-Type", "text/html")
        self.end_headers()

        self.wfile.write(
            b"<html><body>Day 29 Integration Test</body></html>"
        )

    def log_message(self, format, *args):
        pass


def start_test_server():
    server = HTTPServer(("127.0.0.1", 0), TestHandler)

    thread = threading.Thread(
        target=server.serve_forever,
        daemon=True
    )

    thread.start()

    return server


# --------------------------------------------------
# Test helpers
# --------------------------------------------------

passed = 0
failed = 0


def check_result(test_name, condition, details=""):
    global passed, failed

    if condition:
        passed += 1
        print(f"PASS: {test_name}")
    else:
        failed += 1
        print(f"FAIL: {test_name}")

    if details:
        print(f"      {details}")


def finding_text(result):
    return str(result.get("findings", [])).lower()


# --------------------------------------------------
# Day 29 regression and integration tests
# --------------------------------------------------

def main():

    print("=" * 60)
    print("DAY 29: REGRESSION AND INTEGRATION TESTING")
    print("=" * 60)

    server = start_test_server()
    target = f"http://127.0.0.1:{server.server_port}"

    try:
        # Test 1: Successful HTTP response
        result = scan_target(target)

        check_result(
            "Successful HTTP response",
            result.get("status_code") == 200,
            f"Status code: {result.get('status_code')}"
        )

        # Test 2: Scanner returns the expected structure
        required_keys = {
            "target",
            "final_url",
            "status_code",
            "response_time",
            "findings"
        }

        check_result(
            "Successful scan result structure",
            required_keys.issubset(result.keys()),
            f"Returned keys: {list(result.keys())}"
        )

        # Test 3: Invalid X-Content-Type-Options detection
        text = finding_text(result)

        check_result(
            "Invalid security header detection",
            "x-content-type-options" in text
            and "invalid" in text,
            "Checking for an invalid X-Content-Type-Options finding"
        )

        # Test 4: Insecure cookie detection
        check_result(
            "Cookie security detection",
            "test_session" in text
            or (
                "secure" in text
                and "httponly" in text
            ),
            "Checking whether insecure cookie attributes are reported"
        )

        # Test 5: Connection error handling
        with patch(
            "scanner.http_scanner.requests.get",
            side_effect=ConnectionError("Day 29 test connection failure")
        ):
            result = scan_target(
                "http://127.0.0.1:59999"
            )

        error_text = result.get("error", "").lower()

        check_result(
            "Connection error handling",
            "error" in result
            and (
                "connect" in error_text
                or "connection" in error_text
            ),
            f"Returned error: {result.get('error')}"
        )

        # Test 6: HTTP 500 handling
        with patch(
            "scanner.http_scanner.requests.get"
        ) as mock_get:

            class FakeResponse:
                url = target
                status_code = 500
                headers = {}
                cookies = {}
                text = "Internal Server Error"

            mock_get.return_value = FakeResponse()

            result = scan_target(target)

        check_result(
            "HTTP 500 response handling",
            result.get("status_code") == 500,
            f"Status code: {result.get('status_code')}"
        )

    finally:
        server.shutdown()
        server.server_close()

    print("\n" + "=" * 60)
    print(f"Total tests: {passed + failed}")
    print(f"Passed: {passed}")
    print(f"Failed: {failed}")

    if failed == 0:
        print("SUCCESS: All Day 29 tests passed.")
    else:
        print("ACTION REQUIRED: Review the failed tests.")

    print("=" * 60)


if __name__ == "__main__":
    main()
