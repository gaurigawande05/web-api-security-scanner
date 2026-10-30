def check_cors(response):

    findings = []

    origin = response.headers.get(
        "Access-Control-Allow-Origin"
    )

    credentials = response.headers.get(
        "Access-Control-Allow-Credentials"
    )

    if origin == "*":

        findings.append({
            "type": "CORS",
            "name": "Wildcard CORS Configuration",
            "severity": "Medium",
            "url": response.url,
            "evidence": f"Access-Control-Allow-Origin: {origin}"
        })

    if origin == "*" and credentials == "true":

        findings.append({
            "type": "CORS",
            "name": "Potentially Risky CORS Credentials Configuration",
            "severity": "High",
            "url": response.url,
            "evidence": (
                f"Origin: {origin}, "
                f"Credentials: {credentials}"
            )
        })

    return findings