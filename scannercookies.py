from http.cookies import SimpleCookie


def check_cookies(response):
    findings = []

    # Retrieve Set-Cookie headers.
    raw = getattr(response, "raw", None)
    raw_headers = getattr(raw, "headers", None)

    if raw_headers is not None and hasattr(raw_headers, "getlist"):
        cookie_headers = raw_headers.getlist("Set-Cookie")
    else:
        cookie_header = response.headers.get("Set-Cookie")
        cookie_headers = [cookie_header] if cookie_header else []

    # No cookies found.
    if not cookie_headers:
        return findings

    # Inspect each cookie separately.
    for cookie_header in cookie_headers:
        if not cookie_header:
            continue

        parsed_cookie = SimpleCookie()

        try:
            parsed_cookie.load(cookie_header)
        except (TypeError, ValueError):
            continue

        # Skip cookies that could not be parsed.
        if not parsed_cookie:
            continue

        for cookie_name, cookie in parsed_cookie.items():

            # Check Secure attribute.
            if not cookie["secure"]:
                findings.append({
                    "type": "Cookie Security",
                    "name": f"Cookie '{cookie_name}' Missing Secure Attribute",
                    "severity": "Medium",
                    "url": response.url,
                    "evidence": cookie_header
                })

            # Check HttpOnly attribute.
            if not cookie["httponly"]:
                findings.append({
                    "type": "Cookie Security",
                    "name": f"Cookie '{cookie_name}' Missing HttpOnly Attribute",
                    "severity": "Medium",
                    "url": response.url,
                    "evidence": cookie_header
                })

            # Check SameSite attribute.
            if not cookie["samesite"]:
                findings.append({
                    "type": "Cookie Security",
                    "name": f"Cookie '{cookie_name}' Missing SameSite Attribute",
                    "severity": "Low",
                    "url": response.url,
                    "evidence": cookie_header
                })

    return findings
