from scanner.http_scanner import scan_target


def run_test(test_name, target, expected_result):
    print("\n" + "=" * 65)
    print("Test:", test_name)
    print("Target:", target)

    try:
        result = scan_target(target)

        print("Scanner returned a result.")

        if not isinstance(result, dict):
            print("FAIL: Expected a dictionary result.")
            print("Actual result:", repr(result))
            return False

        print("Result keys:", list(result.keys()))

        if expected_result == "success":
            # A successful scan should not contain a top-level error.
            if result.get("error"):
                print("FAIL: Unexpected error:", result["error"])
                return False

            print("PASS: Scan completed without a top-level error.")
            print("Result:", result)
            return True

        if expected_result == "error":
            # A failed connection should be reported clearly.
            if result.get("error"):
                print("PASS: Error was handled.")
                print("Error message:", result["error"])
                return True

            print(
                "REVIEW: No top-level error was returned. "
                "Check the scanner's result structure."
            )
            print("Result:", result)
            return False

    except Exception as error:
        print("FAIL: An exception escaped from scan_target().")
        print("Exception type:", type(error).__name__)
        print("Exception message:", str(error))
        return False


def main():
    tests = [
        {
            "name": "Successful local scan",
            "target": "http://127.0.0.1:5000",
            "expected": "success",
        },
        {
            "name": "Connection refused",
            "target": "http://127.0.0.1:59999",
            "expected": "error",
        },
    ]

    results = []

    for test in tests:
        passed = run_test(
            test["name"],
            test["target"],
            test["expected"],
        )

        results.append((test["name"], passed))

    print("\n" + "=" * 65)
    print("DAY 20 TEST SUMMARY")
    print("=" * 65)

    for name, passed in results:
        print(f"{name}: {'PASS' if passed else 'FAIL'}")

    passed_count = sum(1 for _, passed in results if passed)

    print(f"\nPassed: {passed_count}/{len(results)}")

    if passed_count == len(results):
        print("All Day 20 connection tests passed.")
    else:
        print("Some tests need investigation.")


if __name__ == "__main__":
    main()
