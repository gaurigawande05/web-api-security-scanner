from types import SimpleNamespace

from scanner.headers import check_headers
from scanner.cookies import check_cookies


def create_response(url, headers, raw=None):
    """Create a simulated HTTP response for testing."""
    return SimpleNamespace(
        url=url,
        headers=headers,
        raw=raw
    )


def test_header_detection():
    """Test missing-header detection and finding structure."""

    print("\n" + "=" * 65)
    print("TEST 1: SECURITY-HEADER DETECTION")
    print("=" * 65)

    response = create_response(
        "https://example.test",
        {
            "Content-Security-Policy": "default-src 'self'",
            "X-Content-Type-Options": "nosniff",
            "X-Frame-Options": "DENY",
            "Strict-Transport-Security": "max-age=31536000",
            "Referrer-Policy": "strict-origin-when-cross-origin",
        }
    )

    findings = check_headers(response)

    expected_missing = "Missing Permissions-Policy"

    missing_names = [
        finding.get("name")
        for finding in findings
        if finding.get("name", "").startswith("Missing ")
    ]

    passed = expected_missing in missing_names

    print("Expected missing header:", expected_missing)
    print("Actual missing headers:", missing_names)
    print("Result:", "PASS" if passed else "FAIL")

    # Verify that each returned finding has the expected fields.
    required_fields = {
        "type",
        "name",
        "severity",
        "url",
        "evidence",
    }

    structure_ok = all(
        required_fields.issubset(finding.keys())
        for finding in findings
    )

    print(
        "Finding structure:",
        "PASS" if structure_ok else "FAIL"
    )

    return passed and structure_ok


def test_cookie_detection():
    """Test cookie detection using a simulated response."""

    print("\n" + "=" * 65)
    print("TEST 2: COOKIE DETECTION")
    print("=" * 65)

    # This response deliberately contains no cookies.
    response = create_response(
        "https://example.test",
        {}
    )

    findings = check_cookies(response)

    # No Set-Cookie header means there are no cookie attributes
    # to evaluate in this particular response.
    passed = findings == []

    print("Expected findings: []")
    print("Actual findings:", findings)
    print("Result:", "PASS" if passed else "FAIL")

    return passed


def main():
    results = []

    results.append(
        ("Security-header detection", test_header_detection())
    )

    results.append(
        ("Cookie detection with no cookies", test_cookie_detection())
    )

    print("\n" + "=" * 65)
    print("DAY 21 TEST SUMMARY")
    print("=" * 65)

    for name, passed in results:
        print(f"{name}: {'PASS' if passed else 'FAIL'}")

    passed_count = sum(
        1 for _, passed in results if passed
    )

    print(f"\nPassed: {passed_count}/{len(results)}")

    if passed_count == len(results):
        print("All Day 21 baseline tests passed.")
    else:
        print("Some tests need investigation.")


if __name__ == "__main__":
    main()
