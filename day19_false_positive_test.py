from types import SimpleNamespace
from scanner.headers import check_headers


# Security headers checked by the scanner.
REQUIRED_HEADERS = [
    "Content-Security-Policy",
    "X-Content-Type-Options",
    "X-Frame-Options",
    "Strict-Transport-Security",
    "Referrer-Policy",
    "Permissions-Policy",
]


def create_response(url, headers):
    """Create a simulated HTTP response."""
    return SimpleNamespace(
        url=url,
        headers=headers
    )


def get_header_findings(response):
    """Return findings produced by the security-header detector."""
    findings = check_headers(response)

    return [
        finding
        for finding in findings
        if finding.get("type") == "Security Headers"
    ]


test_cases = [
    {
        "name": "All required headers present over HTTPS",
        "url": "https://example.test",
        "headers": {
            "Content-Security-Policy": "default-src 'self'",
            "X-Content-Type-Options": "nosniff",
            "X-Frame-Options": "DENY",
            "Strict-Transport-Security": "max-age=31536000",
            "Referrer-Policy": "strict-origin-when-cross-origin",
            "Permissions-Policy": "camera=(), microphone=()",
        },
        "expected_missing": [],
    },
    {
        "name": "All headers missing over HTTPS",
        "url": "https://example.test",
        "headers": {},
        "expected_missing": [
            "Missing Content-Security-Policy",
            "Missing X-Content-Type-Options",
            "Missing X-Frame-Options",
            "Missing Strict-Transport-Security",
            "Missing Referrer-Policy",
            "Missing Permissions-Policy",
        ],
    },
    {
        "name": "Only CSP missing over HTTPS",
        "url": "https://example.test",
        "headers": {
            "X-Content-Type-Options": "nosniff",
            "X-Frame-Options": "DENY",
            "Strict-Transport-Security": "max-age=31536000",
            "Referrer-Policy": "strict-origin-when-cross-origin",
            "Permissions-Policy": "camera=(), microphone=()",
        },
        "expected_missing": [
            "Missing Content-Security-Policy",
        ],
    },
    {
        "name": "All non-HSTS headers present over HTTP",
        "url": "http://example.test",
        "headers": {
            "Content-Security-Policy": "default-src 'self'",
            "X-Content-Type-Options": "nosniff",
            "X-Frame-Options": "DENY",
            "Referrer-Policy": "strict-origin-when-cross-origin",
            "Permissions-Policy": "camera=(), microphone=()",
        },
        "expected_missing": [],
    },
    {
        "name": "One non-HSTS header missing over HTTP",
        "url": "http://example.test",
        "headers": {
            "Content-Security-Policy": "default-src 'self'",
            "X-Content-Type-Options": "nosniff",
            "X-Frame-Options": "DENY",
            "Referrer-Policy": "strict-origin-when-cross-origin",
        },
        "expected_missing": [
            "Missing Permissions-Policy",
        ],
    },
]


all_passed = True

print("\nDay 19: False Positive and False Negative Testing")
print("=" * 70)

for test in test_cases:
    response = create_response(
        test["url"],
        test["headers"]
    )

    findings = get_header_findings(response)

    actual_missing = sorted(
        finding["name"]
        for finding in findings
        if finding["name"].startswith("Missing ")
    )

    expected_missing = sorted(test["expected_missing"])

    unexpected_findings = sorted(
        set(actual_missing) - set(expected_missing)
    )

    missed_findings = sorted(
        set(expected_missing) - set(actual_missing)
    )

    passed = actual_missing == expected_missing

    if not passed:
        all_passed = False

    print("\nTest:", test["name"])
    print("URL:", test["url"])
    print("Expected missing headers:", expected_missing)
    print("Actual missing headers:  ", actual_missing)
    print("Unexpected findings:     ", unexpected_findings)
    print("Missed findings:         ", missed_findings)
    print("Result:", "PASS" if passed else "FAIL")


print("\n" + "=" * 70)

if all_passed:
    print(f"SUCCESS: All {len(test_cases)} tests passed.")
else:
    print("FAILURE: One or more tests failed.")

print("=" * 70)