from core.database import init_db, get_scan_history, get_scan_by_id

print("Starting database verification...")

# Ensure the database and scans table exist
init_db()
print("PASS: Database initialized.")

# Retrieve all previous scans
history = get_scan_history()

print(f"PASS: Scan history retrieved.")
print(f"Total saved scans: {len(history)}")

if history:
    latest_scan = history[0]
    scan_id = latest_scan["id"]

    print("\nLatest saved scan:")
    print(f"Scan ID: {scan_id}")
    print(f"Target URL: {latest_scan['target_url']}")
    print(f"HTTP Status: {latest_scan['status_code']}")
    print(f"Response Time: {latest_scan['response_time']} seconds")
    print(f"Findings Count: {latest_scan['findings_count']}")
    print(f"Scan Date: {latest_scan['scan_date']}")

    # Retrieve one scan using its ID
    saved_scan = get_scan_by_id(scan_id)

    if saved_scan is not None:
        print(f"\nPASS: Scan ID {scan_id} retrieved successfully.")
        print(f"Stored findings: {len(saved_scan['findings'])}")
    else:
        print("\nFAIL: Could not retrieve the saved scan.")
else:
    print("\nNo previous scans found. Run a scan first.")

