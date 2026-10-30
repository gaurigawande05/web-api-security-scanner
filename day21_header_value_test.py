from types import SimpleNamespace

from scanner.headers import check_headers


def create_response(url, headers):
    """Create a simulated HTTP response for testing."""
    return SimpleNamespace(
        url=url,
        headers=headers
    )


def run_test(test_name, response, expected_finding):
    """Run one header-value test."""

    findings = check_headers(response)

    actual_finding = any(
        finding.get("name") == expected_finding
        for finding in findings
    )

    print(f"\nTest: {test_name}")
    print(f"Expected finding: {expected_finding}")
    print(
        "Result:",
        "PASS" if actual_finding else "FAIL"
    )

    if not actual_finding:
        print("Actual findings:", [
            finding.get("name") for finding in findings
        ])

    return actual_finding


def main():
    results = []

    # Test 1: Invalid X-Content-Type-Options value.
    response = create_response(
        "https://example.test",
        {
            "X-Content-Type-Options": "invalid-value",
            "X-Frame-Options": "DENY",
            "Content-Security-Policy": "default-src 'self'",
            "Strict-Transport-Security": "max-age=31536000",
            "Referrer-Policy": "strict-origin",
            "Permissions-Policy": "camera=()",
        }
    )

    results.append(
        run_test(
            "Invalid X-Content-Type-Options value",
            response,
            "Invalid X-Content-Type-Options"
        )
    )

    # Test 2: Unrecognized X-Frame-Options value.
    response = create_response(
        "https://example.test",
        {
            "X-Content-Type-Options": "nosniff",
            "X-Frame-Options": "ALLOWALL",
            "Content-Security-Policy": "default-src 'self'",
            "Strict-Transport-Security": "max-age=31536000",
            "Referrer-Policy": "strict-origin",
            "Permissions-Policy": "camera=()",
        }
    )

    results.append(
        run_test(
            "Unrecognized X-Frame-Options value",
            response,
            "Invalid X-Frame-Options"
        )
    )

    print("\n" + "=" * 60)
    print("DAY 21 HEADER-VALUE TEST SUMMARY")
    print("=" * 60)

    passed = sum(results)
    print(f"Passed: {passed}/{len(results)}")

    if passed == len(results):
        print("All header-value tests passed.")
    else:
        print(
            "Some tests failed. This may be expected because "
            "the scanner currently checks header presence only."
        )


if __name__ == "__main__":
    main()