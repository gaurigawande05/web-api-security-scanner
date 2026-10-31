import threading
import time
from http.server import BaseHTTPRequestHandler, HTTPServer

from scanner.http_scanner import scan_target


class SlowHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        time.sleep(12)

        try:
            self.send_response(200)
            self.end_headers()
            self.wfile.write(b"Slow response test")
        except (BrokenPipeError, ConnectionAbortedError, ConnectionResetError):
            print("Client closed the connection after its timeout.")

    def log_message(self, format, *args):
        pass


server = HTTPServer(("127.0.0.1", 8765), SlowHandler)
thread = threading.Thread(target=server.serve_forever, daemon=True)
thread.start()

print("Local slow test server started.")
print("Scanner timeout is expected to occur after 10 seconds.")

try:
    result = scan_target("http://127.0.0.1:8765")
    print("Scanner result:", result)

    if result.get("error") == "The request timed out.":
        print("PASS: Scanner handled the timeout correctly.")
    else:
        print("CHECK: Unexpected result. Review the scanner timeout handling.")
finally:
    server.shutdown()
    server.server_close()
    print("Local test server stopped.")
