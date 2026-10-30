from scanner.http_scanner import scan_target

test_targets = [
    "http://127.0.0.1:5000",
    "http://127.0.0.1:59999",
]

for target in test_targets:
    print("=" * 50)
    print("Testing target:", target)

    try:
        result = scan_target(target)
        print("Result:", result)
    except Exception as error:
        print("Unexpected error:", error)
