from urllib.parse import urlparse

SECURITY_HEADERS = {
    "Content-Security-Policy": "Medium",
    "X-Content-Type-Options": "Low",
    "X-Frame-Options": "Low",
    "Strict-Transport-Security": "Medium",
    "Referrer-Policy": "Low",
    "Permissions-Policy": "Low"
}


def is_valid_hsts(value):
    """
    Check whether the HSTS header contains a valid max-age directive.
    This is a basic validation, not a complete RFC compliance check.
    """
    if not value or not value.strip():
        return False

    directives = [
        directive.strip()
        for directive in value.split(";")
        if directive.strip()
    ]

    for directive in directives:
        name, separator, directive_value = directive.partition("=")

        if name.strip().lower() == "max-age":
            if not separator:
                return False

            age = directive_value.strip()

            return age.isdigit()

    return False


def check_headers(response):
    findings = []
    headers = response.headers

    parsed_url = urlparse(response.url)
    is_https = parsed_url.scheme.lower() == "https"

    for header, severity in SECURITY_HEADERS.items():

        # HSTS should be checked only on HTTPS responses.
        if header == "Strict-Transport-Security":
            if not is_https:
                continue

            hsts_value = response.headers.get(header)

            if not hsts_value:
                findings.append({
                    "type": "Security Headers",
                    "name": "Missing Strict-Transport-Security",
                    "severity": "Medium",
                    "url": response.url,
                    "evidence": (
                        "Strict-Transport-Security header "
                        "was missing or empty in the HTTPS response."
                    )
                })

            elif not is_valid_hsts(hsts_value):
                findings.append({
                    "type": "Security Headers",
                    "name": "Invalid Strict-Transport-Security",
                    "severity": "Medium",
                    "url": response.url,
                    "evidence": (
                        f"Invalid HSTS policy: {hsts_value}"
                    )
                })

            continue

        # Check other security headers.
        if header not in response.headers:
            findings.append({
                "type": "Security Headers",
                "name": f"Missing {header}",
                "severity": severity,
                "url": response.url,
                "evidence": (
                    f"{header} header was not present in the "
                    f"{parsed_url.scheme.upper()} response."
                )
            })


    # Validate X-Content-Type-Options.
    x_content_type = headers.get("X-Content-Type-Options")

    if (
        x_content_type is not None
        and x_content_type.strip().lower() != "nosniff"
    ):
        findings.append({
            "type": "Security Headers",
            "name": "Invalid X-Content-Type-Options",
            "severity": "Low",
            "url": response.url,
            "evidence": (
                "Expected X-Content-Type-Options: nosniff, "
                f"but received: {x_content_type}"
            ),
        })

    # Validate X-Frame-Options.
    x_frame_options = headers.get("X-Frame-Options")

    if x_frame_options is not None:
        frame_value = x_frame_options.strip().upper()

        if frame_value not in ("DENY", "SAMEORIGIN"):
            findings.append({
                "type": "Security Headers",
                "name": "Invalid X-Frame-Options",
                "severity": "Low",
                "url": response.url,
                "evidence": (
                    "Expected DENY or SAMEORIGIN, "
                    f"but received: {x_frame_options}"
                ),
            })

    return findings