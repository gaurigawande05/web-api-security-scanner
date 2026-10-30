import inspect
import builtins
import scanner.http_scanner as scanner

print("Scanner file:")
print(scanner.__file__)

print("\nLoaded scan_target function:")
print(inspect.getsource(scanner.scan_target))

print("\nException class checks:")
print("ConnectionError:", builtins.ConnectionError)
print("TimeoutError:", builtins.TimeoutError)

print("\nTesting connection exception directly:")

try:
    try:
        raise builtins.ConnectionError("Diagnostic connection failure")
    except (ConnectionError, TimeoutError) as error:
        print("PASS: Built-in exception handler works")
        print(type(error).__name__, str(error))
except Exception as error:
    print("FAIL:", type(error).__name__, str(error))

print("\nTesting scanner with mocked connection exception:")

from unittest.mock import patch

try:
    with patch(
        "scanner.http_scanner.requests.get",
        side_effect=builtins.ConnectionError("Diagnostic connection failure")
    ):
        result = scanner.scan_target("http://127.0.0.1:59999")

    print("Returned result:", result)

except Exception as error:
    print("Exception escaped scan_target:")
    print(type(error).__name__, str(error))

