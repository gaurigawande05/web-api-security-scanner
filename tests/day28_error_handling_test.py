import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from unittest.mock import patch

from scanner.http_scanner import scan_target


# Test server that returns HTTP 500.
class ErrorTestHandler(BaseHTTPRequestHandler):

    def do_GET(self):
        self.send_response(500)
        self.send_header("Content-Type", "text/plain")
        self.end_headers()
        self.wfile.write(b"Internal Server Error")

    def log_message(self, format, *args):
        # Suppress server logs during testing.
        pass


def test_connection_error():
    """Test whether connection errors are handled correctly."""

    print("\nTest 1: Connection failure")

    try:
        with patch(
            "scanner.http_scanner.requests.get",
            side_effect=ConnectionError("Test connection failure")
        ):
            result = scan_target("http://127.0.0.1:59999")

        if not isinstance(result, dict):
            print("FAIL: Expected a dictionary result")
            print("Actual result:", repr(result))
            return False

        error_message = result.get("error", "")

        if "connection" in error_message.lower():
            print("PASS: Connection error handled correctly")
            print("Returned error:", error_message)
            return True

        print("FAIL: Expected connection error was not returned")
        print("Result:", result)
        return False

    except Exception as error:
        print("FAIL: Connection exception escaped the scanner")
        print(type(error).__name__, str(error))
        return False


def test_timeout_error():
    """Test whether timeout errors are handled correctly."""

    print("\nTest 2: Request timeout")

    try:
        with patch(
            "scanner.http_scanner.requests.get",
            side_effect=TimeoutError("Test request timeout")
        ):
            result = scan_target("http://127.0.0.1:59999")

        if not isinstance(result, dict):
            print("FAIL: Expected a dictionary result")
            print("Actual result:", repr(result))
            return False

        error_message = result.get("error", "")

        if "timeout" in error_message.lower() or "timed out" in error_message.lower():
            print("PASS: Timeout handled correctly")
            print("Returned error:", error_message)
            return True

        print("FAIL: Expected timeout error was not returned")
        print("Result:", result)
        return False

    except Exception as error:
        print("FAIL: Timeout exception escaped the scanner")
        print(type(error).__name__, str(error))
        return False


def test_http_500():
    """Test whether HTTP 500 responses are processed correctly."""

    print("\nTest 3: HTTP 500 response")

    server = HTTPServer(
        ("127.0.0.1", 0),
        ErrorTestHandler
    )

    server_thread = threading.Thread(
        target=server.serve_forever,
        daemon=True
    )
    server_thread.start()

    target_url = f"http://127.0.0.1:{server.server_port}"

    try:
        result = scan_target(target_url)

        if not isinstance(result, dict):
            print("FAIL: Expected a dictionary result")
            print("Actual result:", repr(result))
            return False

        if result.get("status_code") == 500:
            print("PASS: HTTP 500 response processed correctly")
            print("Status code:", result["status_code"])
            print("Response time:", result.get("response_time"), "seconds")
            return True

        print("FAIL: HTTP 500 response was not processed correctly")
        print("Result:", result)
        return False

    except Exception as error:
        print("FAIL: HTTP 500 test raised an exception")
        print(type(error).__name__, str(error))
        return False

    finally:
        server.shutdown()
        server.server_close()
        server_thread.join(timeout=2)


def main():
    print("Day 28: Scanner Error Handling and Reliability Testing")
    print("=" * 60)

    results = []

    results.append(test_connection_error())
    results.append(test_timeout_error())
    results.append(test_http_500())

    passed = sum(results)
    total = len(results)

    print("\n" + "=" * 60)
    print(f"Final Result: {passed}/{total} tests passed")

    if passed == total:
        print("SUCCESS: All Day 28 reliability tests passed.")
    else:
        print("FAILURE: Some tests need further investigation.")


if __name__ == "__main__":
    main()

