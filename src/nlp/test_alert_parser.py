import json
import os
import sys

# Ensure project root is in sys.path
PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

# Safely handle Windows console encodings (e.g. cp1252)
if hasattr(sys.stdout, "reconfigure"):
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

from src.nlp.alert_parser import AlertParser


def main():
    sample_alert = (
        "CYBERSECURITY ALERT\n"
        "Alert ID: SEC-2026-0913-001\n"
        "Timestamp: 2026-09-13 01:48:32\n"
        "Severity: High\n"
        "Event Type: Brute Force Attack\n"
        "Attack Category: Credential Attack\n"
        "Source IP: 185.220.101.45\n"
        "Destination IP: 192.168.1.105\n"
        "Protocol: TCP\n"
        "Destination Port: 22\n"
        "Alert Description:\n"
        "Multiple failed SSH login attempts detected from the same external IP address. "
        "47 failed authentication attempts were recorded within 5 minutes against the server.\n"
        "Failed Login Attempts: 47\n"
        "Time Window: 5 minutes\n"
        "Target Service: SSH\n"
        "Target Account: admin\n"
        "Status: Suspicious Activity Detected\n"
        "Recommended Initial Action:\n"
        "Investigate the source IP, review authentication logs, verify whether the target account was compromised, "
        "and consider blocking the source IP."
    )

    parser = AlertParser()
    parsed = parser.parse(sample_alert)

    print("\n" + "=" * 60)
    print("ALERT PARSER TEST")
    print("=" * 60)

    # 1. ALERT METADATA
    print("\nALERT METADATA")
    print("-" * 60)
    for k, v in parsed["alert_metadata"].items():
        print(f"  {k:18}: {v}")

    # 2. NETWORK CONTEXT
    print("\nNETWORK CONTEXT")
    print("-" * 60)
    for k, v in parsed["network_context"].items():
        print(f"  {k:18}: {v}")

    # 3. BEHAVIORAL EVIDENCE
    print("\nBEHAVIORAL EVIDENCE")
    print("-" * 60)
    for idx, item in enumerate(parsed["behavioral_evidence"], start=1):
        print(f"  [{idx}] {item}")

    # 4. IOC EVIDENCE
    print("\nIOC EVIDENCE")
    print("-" * 60)
    for idx, ioc in enumerate(parsed["ioc_evidence"], start=1):
        print(f"  [{idx}] Type: {ioc['type']:8} | Value: {ioc['value']}")

    # 5. CONTEXT
    print("\nCONTEXT")
    print("-" * 60)
    for k, v in parsed["context"].items():
        print(f"  {k:22}: {v}")

    # 6. RECOMMENDED INITIAL ACTION
    print("\nRECOMMENDED INITIAL ACTION")
    print("-" * 60)
    print(f"  {parsed['recommended_initial_action']}")

    # 7. VALIDATION
    print("\nVALIDATION")
    print("-" * 60)

    checks = []

    # Check 1: Alert ID extracted
    alert_id = parsed["alert_metadata"].get("alert_id")
    check1 = bool(alert_id and alert_id == "SEC-2026-0913-001")
    checks.append(("Alert ID extracted", check1, alert_id))

    # Check 2: Severity extracted
    severity = parsed["alert_metadata"].get("severity")
    check2 = bool(severity and severity.lower() == "high")
    checks.append(("Severity extracted", check2, severity))

    # Check 3: Source IP extracted
    source_ip = parsed["network_context"].get("source_ip")
    check3 = bool(source_ip and source_ip == "185.220.101.45")
    checks.append(("Source IP extracted", check3, source_ip))

    # Check 4: Destination IP extracted
    destination_ip = parsed["network_context"].get("destination_ip")
    check4 = bool(destination_ip and destination_ip == "192.168.1.105")
    checks.append(("Destination IP extracted", check4, destination_ip))

    # Check 5: Port extracted
    port = parsed["network_context"].get("destination_port")
    check5 = bool(port and str(port) == "22")
    checks.append(("Port extracted", check5, port))

    # Check 6: Behavioral evidence is not empty
    behav_ev = parsed.get("behavioral_evidence", [])
    check6 = bool(behav_ev and len(behav_ev) > 0)
    checks.append(("Behavioral evidence is not empty", check6, f"{len(behav_ev)} items"))

    # Check 7: IOC evidence contains the source IP
    ioc_values = [ioc["value"] for ioc in parsed.get("ioc_evidence", [])]
    check7 = "185.220.101.45" in ioc_values
    checks.append(("IOC evidence contains the source IP", check7, "185.220.101.45"))

    # Check 8: Target service extracted
    target_service = parsed["context"].get("target_service")
    check8 = bool(target_service and target_service.upper() == "SSH")
    checks.append(("Target service extracted", check8, target_service))

    all_passed = True
    for desc, passed, val in checks:
        status_str = "PASS" if passed else "FAIL"
        print(f"  [{status_str}] {desc:38} : {val}")
        if not passed:
            all_passed = False

    print("\n" + "=" * 60)
    if all_passed:
        print("Alert parser validation: PASSED")
    else:
        print("Alert parser validation: FAILED")
    print("=" * 60 + "\n")

    if not all_passed:
        sys.exit(1)


if __name__ == "__main__":
    main()
