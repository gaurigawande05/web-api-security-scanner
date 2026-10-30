from scanner.url_validator import validate_url

test_urls = [
    "https://example.com",
    "http://example.com",
    "example.com",
    "",
    "ftp://example.com",
    "javascript:alert(1)",
    "http:///example.com",
    "http://example.com:abc",
    "http://",
]

print("=" * 50)
print("DAY 16 - URL VALIDATION TESTING")
print("=" * 50)

for url in test_urls:
    try:
        is_valid, result = validate_url(url)
        print(f"Input: {url!r}")
        print(f"Valid: {is_valid}")
        print(f"Result: {result}")
    except Exception as error:
        print(f"Input: {url!r}")
        print(f"Error: {error}")

    print("-" * 50)

print("Testing completed.")
