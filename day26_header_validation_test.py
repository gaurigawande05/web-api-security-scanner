from unittest.mock import Mock
from scanner.headers import check_headers


def create_response(headers):
    response = Mock()
    response.url = "https://example.com"
    response.headers = headers
    return response


def run_test(test_name, headers, expected_text, should_be_detected=True):
    response = create_response(headers)
    findings = check_headers(response) or []

    findings_text = str(findings).lower()
    expected = expected_text.lower()

    detected = expected in findings_text

    if detected == should_be_detected:
        print(f"PASS: {test_name}")
    else:
        print(f"FAIL: {test_name}")
        print(f"      Expected detection: {should_be_detected}")
        print(f"      Actual findings: {findings}")


print("Day 26: Security Header Validation Testing")
print("=" * 48)

# Test 1: Invalid X-Content-Type-Options
run_test(
    "Invalid X-Content-Type-Options",
    {
        "X-Content-Type-Options": "invalid-value",
        "Strict-Transport-Security": "max-age=31536000"
    },
    "Invalid X-Content-Type-Options",
    True
)

# Test 2: Invalid X-Frame-Options
run_test(
    "Invalid X-Frame-Options",
    {
        "X-Frame-Options": "INVALID",
        "Strict-Transport-Security": "max-age=31536000"
    },
    "Invalid X-Frame-Options",
    True
)

# Test 3: Valid X-Content-Type-Options
run_test(
    "Valid X-Content-Type-Options",
    {
        "X-Content-Type-Options": "nosniff",
        "Strict-Transport-Security": "max-age=31536000"
    },
    "Invalid X-Content-Type-Options",
    False
)

# Test 4: Valid X-Frame-Options DENY
run_test(
    "Valid X-Frame-Options DENY",
    {
        "X-Frame-Options": "DENY",
        "Strict-Transport-Security": "max-age=31536000"
    },
    "Invalid X-Frame-Options",
    False
)

# Test 5: Valid X-Frame-Options SAMEORIGIN
run_test(
    "Valid X-Frame-Options SAMEORIGIN",
    {
        "X-Frame-Options": "SAMEORIGIN",
        "Strict-Transport-Security": "max-age=31536000"
    },
    "Invalid X-Frame-Options",
    False
)

print("\nDay 26 testing completed.")