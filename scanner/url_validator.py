from urllib.parse import urlparse


def validate_url(url):
    if not isinstance(url, str):
        return False, "URL must be a string."

    url = url.strip()

    if not url:
        return False, "URL cannot be empty."

    # Detect an explicitly supplied scheme.
    parsed = urlparse(url)

    if parsed.scheme:
        if parsed.scheme.lower() not in ("http", "https"):
            return False, "Only HTTP and HTTPS URLs are supported."
    else:
        # Add HTTPS as the default for scheme-less input.
        url = "https://" + url
        parsed = urlparse(url)

    if not parsed.hostname:
        return False, "URL must contain a valid hostname."

    if parsed.username is not None or parsed.password is not None:
        return False, "URLs containing embedded credentials are not allowed."

    try:
        # Accessing port also validates its numeric range.
        port = parsed.port

        if port is not None and not (1 <= port <= 65535):
            return False, "Port must be between 1 and 65535."

    except ValueError:
        return False, "URL contains an invalid port."

    if any(char.isspace() for char in parsed.netloc):
        return False, "URL contains invalid whitespace."

    return True, url
