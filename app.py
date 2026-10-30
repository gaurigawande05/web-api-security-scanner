from flask import Flask, render_template, request, jsonify
from scanner.http_scanner import scan_target
from scanner.url_validator import validate_url
from core.database import (
    init_db,
    save_scan,
    get_scan_history,
    get_scan_by_id
)
from owasp_mapping import get_owasp_info

app = Flask(__name__)

# Initialize the database when the application starts.
init_db()


def enrich_findings(results):
    """Add OWASP-related details to scanner findings."""

    findings = results.get("findings", [])

    for finding in findings:
        finding_name = finding.get("name", "")

        if not finding_name:
            finding_name = finding.get("title", "")

        try:
            info = get_owasp_info(finding_name)
            if isinstance(info, dict):
                finding.setdefault(
                    "description",
                    info.get("description", "Review this security finding.")
                )
                finding.setdefault(
                    "category",
                    info.get("category", "Security configuration")
                )
                finding.setdefault(
                    "reference",
                    info.get("reference", "")
                )
        except (TypeError, KeyError, AttributeError):
            # Keep the original finding if mapping information is unavailable.
            pass

    return results


def validate_target(target):
    """Validate and normalize a target URL."""

    if not target or not target.strip():
        return None, "Please enter a target URL."

    target = target.strip()

    try:
        valid, message = validate_url(target)
    except Exception:
        return None, "The URL could not be validated."

    if not valid:
        return None, message or "Please enter a valid HTTP or HTTPS URL."

    # The validator may return a normalized URL in its message/result.
    # Preserve the project's existing validator behavior.
    if isinstance(message, str) and message.startswith(("http://", "https://")):
        target = message

    return target, None


@app.route("/")
def index():
    """Display the main scanner dashboard."""

    return render_template("index.html", error=None)


@app.route("/scan", methods=["POST"])
def scan():
    """Scan a target submitted from the dashboard."""

    target_input = request.form.get("target", "")
    target, error = validate_target(target_input)

    if error:
        return render_template("index.html", error=error), 400

    try:
        results = scan_target(target)

        if not isinstance(results, dict):
            return render_template(
                "index.html",
                error="The scanner returned an unexpected result."
            ), 500

        results = enrich_findings(results)

        # Display a scanner-level error instead of treating it as a
        # successful security scan.
        if results.get("error"):
            return render_template(
                "index.html",
                error=results["error"]
            ), 502

        scan_id = save_scan(target, results)

        return render_template(
            "results.html",
            results=results,
            target=target,
            scan_id=scan_id
        )

    except Exception as exc:
        app.logger.exception("Dashboard scan failed")
        return render_template(
            "index.html",
            error=f"Scan failed: {exc}"
        ), 500


@app.route("/api/scan", methods=["POST"])
def api_scan():
    """Scan a target submitted as JSON."""

    data = request.get_json(silent=True) or {}
    target_input = data.get("target", "")

    target, error = validate_target(target_input)

    if error:
        return jsonify({"error": error, "findings": []}), 400

    try:
        results = scan_target(target)

        if not isinstance(results, dict):
            return jsonify({
                "error": "The scanner returned an unexpected result.",
                "findings": []
            }), 500

        results = enrich_findings(results)

        if results.get("error"):
            return jsonify(results), 502

        scan_id = save_scan(target, results)
        results["scan_id"] = scan_id

        return jsonify(results), 200

    except Exception:
        app.logger.exception("API scan failed")
        return jsonify({
            "error": "The scan could not be completed.",
            "findings": []
        }), 500


@app.route("/history")
def scan_history():
    """Display previously saved scans."""

    try:
        history = get_scan_history()
        return render_template("history.html", history=history)

    except Exception:
        app.logger.exception("Could not load scan history")
        return (
            "Unable to load scan history. Check the Flask terminal for details.",
            500
        )


@app.route("/history/<int:scan_id>")
def scan_details(scan_id):
    """Display the details of one saved scan."""

    try:
        saved_scan = get_scan_by_id(scan_id)

        if saved_scan is None:
            return "Scan not found.", 404

        # Database findings are already decoded by get_scan_by_id().
        saved_scan = enrich_findings(saved_scan)

        return render_template(
            "scan_details.html",
            scan=saved_scan,
            results=saved_scan
        )

    except Exception:
        app.logger.exception("Could not load saved scan details")
        return (
            "Unable to load scan details. Check the Flask terminal for details.",
            500
        )


@app.errorhandler(404)
def page_not_found(error):
    """Return a normal 404 response for unknown pages."""

    return "Page not found.", 404


if __name__ == "__main__":
    app.run(
        host="127.0.0.1",
        port=5000,
        debug=True
    )

