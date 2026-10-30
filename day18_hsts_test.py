from types import SimpleNamespace
from scanner.headers import check_headers


def create_response(url, headers):
    """Create a simulated HTTP response for testing."""
    return SimpleNamespace(
        url=url,
        headers=headers
    )


test_cases = [
    {
        "name": "HTTP without HSTS",
        "url": "http://example.test",
        "headers": {},
        "expected_finding": None
    },
    {
        "name": "HTTPS without HSTS",
        "url": "https://example.test",
        "headers": {},
        "expected_finding": "Missing Strict-Transport-Security"
    },
    {
        "name": "HTTPS with valid HSTS",
        "url": "https://example.test",
        "headers": {
            "Strict-Transport-Security": "max-age=31536000"
        },
        "expected_finding": None
    },
    {
        "name": "HTTPS with empty HSTS value",
        "url": "https://example.test",
        "headers": {
            "Strict-Transport-Security": ""
        },
        "expected_finding": "Missing Strict-Transport-Security"
    },
    {
        "name": "HTTPS with invalid max-age",
        "url": "https://example.test",
        "headers": {
            "Strict-Transport-Security": "max-age=abc"
        },
        "expected_finding": "Invalid Strict-Transport-Security"
    },
    {
        "name": "HTTPS with HSTS missing max-age",
        "url": "https://example.test",
        "headers": {
            "Strict-Transport-Security": "includeSubDomains"
        },
        "expected_finding": "Invalid Strict-Transport-Security"
    },
    {
        "name": "HTTPS with zero max-age",
        "url": "https://example.test",
        "headers": {
            "Strict-Transport-Security": "max-age=0"
        },
        "expected_finding": None
    }
]


all_passed = True

print("\nHSTS Detection Test Started")
print("=" * 65)

for test in test_cases:
    response = create_response(
        test["url"],
        test["headers"]
    )

    findings = check_headers(response)

    hsts_findings = [
        finding["name"]
        for finding in findings
        if finding["name"] in (
            "Missing Strict-Transport-Security",
            "Invalid Strict-Transport-Security"
        )
    ]

    actual_finding = hsts_findings[0] if hsts_findings else None

    passed = actual_finding == test["expected_finding"]

    if not passed:
        all_passed = False

    print(f"\nTest: {test['name']}")
    print(f"URL: {test['url']}")
    print(f"Expected finding: {test['expected_finding']}")
    print(f"Actual finding:   {actual_finding}")
    print(f"Result: {'PASS' if passed else 'FAIL'}")


print("\n" + "=" * 65)

if all_passed:
    print(f"SUCCESS: All {len(test_cases)} HSTS tests passed.")
else:
    print("FAILURE: Some HSTS tests did not match expectations.")

print("=" * 65)