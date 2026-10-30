# Web & API Security Scanner Using Python

A Python-based web security scanning project developed to identify selected HTTP security configuration issues and demonstrate practical web security testing.

## Project Overview

The Web & API Security Scanner sends HTTP requests to a specified target and evaluates selected security-related response characteristics. It reports findings to help developers understand potential security configuration weaknesses.

This project was developed as part of a cybersecurity internship, with an emphasis on improving detection reliability, error handling, and testing.

## Features

* **HTTP response analysis:** Records HTTP response status and response time.
* **Security header analysis:** Checks selected security headers, including Content-Security-Policy, X-Content-Type-Options, X-Frame-Options, Strict-Transport-Security, Referrer-Policy, and Permissions-Policy.
* **Cookie security checks:** Evaluates selected cookie attributes, including Secure, HttpOnly, and SameSite.
* **CORS checks:** Examines selected Cross-Origin Resource Sharing response configuration.
* **Technology disclosure checks:** Identifies selected technology information exposed through HTTP response headers.
* **Error handling:** Handles common connection failures, request timeouts, and HTTP response errors.
* **Web interface:** Provides a browser-based interface for submitting scan targets and viewing findings.
* **Scan history:** Supports saving and viewing previous scans if database history is enabled in the configured application.

## Technologies Used

* Python
* Flask
* Requests
* SQLite, if enabled in the application
* HTML and CSS
* JavaScript, where used by the frontend

## Project Structure

The project may contain the following components:

```text
web-api-security-scanner/
├── app.py
├── scanner/
│   ├── http_scanner.py
│   ├── headers.py
│   ├── cookies.py
│   ├── cors.py
│   └── technology.py
├── core/
├── templates/
├── static/
├── requirements.txt
├── .gitignore
└── README.md
```

Adjust this structure to match the files actually present in your repository.

## Installation

### 1. Clone the repository

```bash
git clone https://github.com/YOUR-USERNAME/web-api-security-scanner.git
cd web-api-security-scanner
```

Replace `YOUR-USERNAME` with your GitHub username.

### 2. Create a virtual environment

Windows:

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
```

### 3. Install dependencies

```bash
python -m pip install -r requirements.txt
```

### 4. Run the application

```bash
python app.py
```

Open the local address configured by the application, typically:

```text
http://127.0.0.1:5000
```

## How to Use

1. Start the Flask application.
2. Open the scanner in your browser.
3. Enter a target URL that you own or are explicitly authorized to test.
4. Start the scan.
5. Review the response information and detected findings.
6. Review scan history if the feature is enabled.

## Testing and Reliability

Testing during development included selected checks for:

* URL validation.
* Missing and invalid security header values.
* Cookie security attributes.
* HTTP response handling.
* Connection failures and timeouts.
* HTTP 500 response processing.
* Regression and integration behaviour.

Record the final test counts here only after running the corresponding tests.

## Limitations

This project checks selected HTTP security configurations and response characteristics. It does not detect every web application vulnerability and is not a substitute for a comprehensive penetration test.

Detection results depend on the target's responses and the checks implemented in the scanner. Findings should be manually verified before being treated as confirmed vulnerabilities.

## Responsible Use

Use this scanner only against applications you own or have explicit permission to test.

Do not use it to scan unauthorized systems, disrupt services, or access data without permission.

## Future Improvements

* Expand detection coverage for web and API security issues.
* Improve finding validation and reduce false positives.
* Add structured report export.
* Expand automated regression and integration tests.
* Improve severity classification and finding evidence.

## Project Status

Developed as a hands-on cybersecurity internship project. Features and testing coverage may evolve as the scanner is improved.
