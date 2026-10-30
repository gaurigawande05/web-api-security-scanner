OWASP_REFERENCES = {
    "Missing Content-Security-Policy": {
        "description": (
            "The response does not include a Content Security Policy header "
            "to help control the sources of browser-loaded content."
        ),
        "owasp_category": "Context-dependent; review security configuration",
        "reference": (
            "https://cheatsheetseries.owasp.org/cheatsheets/"
            "Content_Security_Policy_Cheat_Sheet.html"
        ),
    },

    "Missing X-Content-Type-Options": {
        "description": (
            "The response does not include X-Content-Type-Options: nosniff."
        ),
        "owasp_category": "Security Misconfiguration — context-dependent",
        "reference": "https://owasp.org/Top10/",
    },

    "Missing X-Frame-Options": {
        "description": (
            "The response does not include an X-Frame-Options header. "
            "Check whether CSP frame-ancestors already provides framing protection."
        ),
        "owasp_category": "Clickjacking protection; context-dependent",
        "reference": (
            "https://cheatsheetseries.owasp.org/cheatsheets/"
            "Clickjacking_Defense_Cheat_Sheet.html"
        ),
    },

    "Missing Strict-Transport-Security": {
        "description": (
            "The HTTPS response does not include a "
            "Strict-Transport-Security header."
        ),
        "owasp_category": "Transport security; context-dependent",
        "reference": (
            "https://cheatsheetseries.owasp.org/cheatsheets/"
            "HTTP_Strict_Transport_Security_Cheat_Sheet.html"
        ),
    },

    "Missing Referrer-Policy": {
        "description": (
            "The response does not include a Referrer-Policy header "
            "to control how much referrer information the browser sends."
        ),
        "owasp_category": "Security Configuration — context-dependent",
        "reference": "https://owasp.org/Top10/",
    },

    "Missing Permissions-Policy": {
        "description": (
            "The response does not include a Permissions-Policy header "
            "to control access to supported browser features."
        ),
        "owasp_category": "Security Configuration — context-dependent",
        "reference": "https://owasp.org/Top10/",
    },

    "Cookie Security": {
        "description": (
            "A cookie may be missing one or more security attributes, "
            "such as Secure, HttpOnly, or SameSite."
        ),
        "owasp_category": "Session management; context-dependent",
        "reference": "https://owasp.org/www-project-web-security-testing-guide/",
    },

    "Server Technology Disclosed": {
        "description": (
            "The response reveals server or framework information "
            "that may help an attacker fingerprint the application."
        ),
        "owasp_category": "Security Misconfiguration — context-dependent",
        "reference": "https://owasp.org/Top10/",
    },
}


def get_owasp_info(finding_name):
    """Return OWASP-related information for a scanner finding."""

    if not finding_name:
        return {
            "description": "Review this finding and assess its security impact.",
            "owasp_category": "Not mapped",
            "reference": "https://owasp.org/Top10/",
        }

    if finding_name in OWASP_REFERENCES:
        return OWASP_REFERENCES[finding_name]

    for key, info in OWASP_REFERENCES.items():
        if key in finding_name:
            return info

    return {
        "description": "Review this finding and assess its security impact.",
        "owasp_category": "Not mapped",
        "reference": "https://owasp.org/Top10/",
    }