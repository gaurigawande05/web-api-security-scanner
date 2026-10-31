import time
import requests

from scanner.headers import check_headers
from scanner.cookies import check_cookies
from scanner.technology import detect_technology
from scanner.cors import check_cors


def scan_target(target):
    """
    Scan a target URL for HTTP security configuration issues.
    Return scan results as a dictionary.
    """

    findings = []
    start_time = time.time()

    try:
        response = requests.get(
            target,
            timeout=10,
            allow_redirects=True,
            headers={"User-Agent": "WebAPISecurityScanner/1.0"}
        )

        response_time = round(time.time() - start_time, 2)

        findings.append({
            "type": "HTTP",
            "name": "HTTP Response",
            "severity": "Info",
            "url": response.url,
            "evidence": f"Status Code: {response.status_code}"
        })

        try:
            findings.extend(check_headers(response) or [])
        except Exception as error:
            print(f"Header check failed: {error}")

        try:
            findings.extend(check_cookies(response) or [])
        except Exception as error:
            print(f"Cookie check failed: {error}")

        try:
            findings.extend(check_cors(response) or [])
        except Exception as error:
            print(f"CORS check failed: {error}")

        try:
            findings.extend(detect_technology(response) or [])
        except Exception as error:
            print(f"Technology detection failed: {error}")

        return {
            "target": target,
            "final_url": response.url,
            "status_code": response.status_code,
            "response_time": response_time,
            "findings": findings
        }

    except requests.exceptions.Timeout as error:
        return {
            "target": target,
            "error": f"The request timed out: {error}",
            "findings": []
        }

    except requests.exceptions.ConnectionError as error:
        return {
            "target": target,
            "error": f"Unable to connect to the target: {error}",
            "findings": []
        }

    except requests.exceptions.RequestException as error:
        return {
            "target": target,
            "error": f"Unable to scan target: {error}",
            "findings": []
        }

    except (ConnectionError, TimeoutError) as error:
        return {
            "target": target,
            "error": (
                f"Connection or timeout error: "
                f"{type(error).__name__}: {error}"
            ),
            "findings": []
        }

    except Exception as error:
        return {
            "target": target,
            "error": (
                f"Unexpected scanner error: "
                f"{type(error).__name__}: {error}"
            ),
            "findings": []
        }
