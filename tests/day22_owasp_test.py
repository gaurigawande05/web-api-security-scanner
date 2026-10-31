from owasp_mapping import get_owasp_info

test_findings = [
    "Missing Content-Security-Policy",
    "Missing X-Content-Type-Options",
    "Missing X-Frame-Options",
    "Missing Strict-Transport-Security",
    "Cookie Security",
    "Server Technology Disclosed",
    "Unknown Finding"
]

for finding_name in test_findings:
    info = get_owasp_info(finding_name)

    print("=" * 60)
    print("Finding:", finding_name)
    print("Description:", info["description"])
    print("OWASP category:", info["owasp_category"])
    print("Reference:", info["reference"])

print("=" * 60)
print("OWASP mapping test completed.")
