from scanner.http_scanner import scan_target
from unittest.mock import patch

print("Testing connection error handling...")
print("=" * 40)

try:
    with patch(
        "scanner.http_scanner.requests.get",
        side_effect=ConnectionError("Test failure")
    ):
        result = scan_target("http://127.0.0.1:59999")

    print("Returned result:")
    print(result)

    if any(
        finding.get("name") == "Target Connection Error"
        for finding in result
    ):
        print("\nPASS: Connection error handled correctly")
    else:
        print("\nFAIL: Expected connection error finding")

except Exception as exc:
    print("\nFAIL: Exception escaped the scanner")
    print(type(exc).__name__, str(exc))
