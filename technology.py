def detect_technology(response):
    """
    Detect basic technology information disclosed
    through HTTP response headers.
    """

    findings = []

    # Check whether the server header reveals technology information
    server = response.headers.get("Server", "")

    if server:
        findings.append({
            "name": "Server Technology Disclosed",
            "type": "Information Disclosure",
            "severity": "Low",
            "url": response.url,
            "evidence": f"Server: {server}"
        })

    # Check whether the X-Powered-By header reveals technology information
    powered_by = response.headers.get("X-Powered-By", "")

    if powered_by:
        findings.append({
            "name": "Technology Information Disclosed",
            "type": "Information Disclosure",
            "severity": "Low",
            "url": response.url,
            "evidence": f"X-Powered-By: {powered_by}"
        })

    return findings