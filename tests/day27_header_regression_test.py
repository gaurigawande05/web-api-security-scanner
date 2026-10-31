from unittest.mock import Mock
from scanner.headers import check_headers


def create_response(headers, url="https://example.com"):
    response = Mock()
    response.url = url
    response.headers = headers
    return response


def run_test(test_name, headers, expected_text, should_be_detected=True,
             url="https://example.com"):

    response = create_response(headers, url)
    findings = check_headers(response) or []
    findings_text = str(findings).lower()

    detected = expected_text.lower() in findings_text

    if detected == should_be_detected:
        print(f"PASS: {test_name}")
    else:
        print(f"FAIL: {test_name}")
        print(f"Expected detection: {should_be_detected}")
        print(f"Actual findings: {findings}")


print("Day 27: Security Header Detection Regression Tests")
print("=" * 55)

# Test 1: Missing Content Security Policy
run_test(
    "Missing CSP detection",
    {
        "Strict-Transport-Security": "max-age=31536000"
    },
    "Content-Security-Policy",
    True
)

# Test 2: Valid X-Content-Type-Options
run_test(
    "Valid X-Content-Type-Options",
    {
        "X-Content-Type-Options": "nosniff",
        "Strict-Transport-Security": "max-age=31536000"
    },
    "Invalid X-Content-Type-Options",
    False
)

# Test 3: Invalid X-Content-Type-Options
run_test(
    "Invalid X-Content-Type-Options",
    {
        "X-Content-Type-Options": "invalid-value",
        "Strict-Transport-Security": "max-age=31536000"
    },
    "Invalid X-Content-Type-Options",
    True
)

# Test 4: Valid X-Frame-Options
run_test(
    "Valid X-Frame-Options",
    {
        "X-Frame-Options": "DENY",
        "Strict-Transport-Security": "max-age=31536000"
    },
    "Invalid X-Frame-Options",
    False
)

# Test 5: Invalid X-Frame-Options
run_test(
    "Invalid X-Frame-Options",
    {
        "X-Frame-Options": "INVALID",
        "Strict-Transport-Security": "max-age=31536000"
    },
    "Invalid X-Frame-Options",
    True
)

# Test 6: Missing HSTS on HTTPS
run_test(
    "Missing HSTS detection on HTTPS",
    {
        "Content-Security-Policy": "default-src 'self'",
        "X-Content-Type-Options": "nosniff",
        "X-Frame-Options": "DENY"
    },
    "Missing Strict-Transport-Security",
    True
)

# Test 7: HSTS should not be flagged as missing on HTTP
run_test(
    "HSTS not required on HTTP",
    {
        "Content-Security-Policy": "default-src 'self'",
        "X-Content-Type-Options": "nosniff",
        "X-Frame-Options": "DENY"
    },
    "Missing Strict-Transport-Security",
    False,
    url="http://example.com"
)

print("\nDay 27 regression testing completed.")
