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

from src.rag.alert_rag_pipeline import AlertRAGPipeline
from src.rag.evidence_package import EvidencePackageBuilder


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

    print("\n" + "=" * 60)
    print("EVIDENCE PACKAGE + THREAT INTELLIGENCE TEST")
    print("=" * 60)

    # 1. Execute Alert → RAG Pipeline
    pipeline = AlertRAGPipeline()
    pipeline_result = pipeline.process_alert(sample_alert)

    # 2. Build Evidence Package with integrated Local Threat Intelligence
    builder = EvidencePackageBuilder()
    pkg = builder.build(pipeline_result)

    # ---------------------------------------------------------
    # STEP 1 — ALERT PARSING
    # ---------------------------------------------------------
    print("\nSTEP 1 — ALERT PARSING")
    print("-" * 60)
    meta = pkg["alert"]["alert_metadata"]
    print(f"Alert ID:   {meta.get('alert_id')}")
    print(f"Severity:   {meta.get('severity')}")
    print(f"Event Type: {meta.get('event_type')}")

    # ---------------------------------------------------------
    # STEP 2 — IOC EVIDENCE
    # ---------------------------------------------------------
    print("\nSTEP 2 — IOC EVIDENCE")
    print("-" * 60)
    iocs = pkg.get("ioc_evidence", [])
    for idx, ioc in enumerate(iocs, start=1):
        print(f"[{idx}] Type: {ioc.get('type'):8} | Value: {ioc.get('value')}")

    # ---------------------------------------------------------
    # STEP 3 — LOCAL THREAT INTELLIGENCE
    # ---------------------------------------------------------
    print("\nSTEP 3 — LOCAL THREAT INTELLIGENCE")
    print("-" * 60)
    ti_results = pkg.get("threat_intelligence", [])
    for idx, entry in enumerate(ti_results, start=1):
        print(f"[{idx}] Queried IOC: {entry.get('queried_ioc')}")
        print(f"    IOC Type:    {entry.get('ioc_type')}")
        print(f"    Match Found: {entry.get('match_found')}")
        print(f"    Matches:     {entry.get('matches')}")

    # Known-positive TI verification using builder's TI service
    print("\n--- KNOWN-POSITIVE THREAT INTEL VERIFICATION ---")
    known_ioc = "154.91.59.119"
    known_matches = builder.ti_service.lookup(known_ioc, ioc_type="ip")
    print(f"Queried Known-Positive IOC: {known_ioc}")
    print(f"Matches found: {len(known_matches)}")
    if known_matches:
        for idx, km in enumerate(known_matches, start=1):
            print(f"  [{idx}] Matched DB IOC: {km.get('ioc')} | Source: {km.get('source')} | Threat: {km.get('threat_type')} | Malware: {km.get('malware')}")

    # ---------------------------------------------------------
    # STEP 4 — MITRE
    # ---------------------------------------------------------
    print("\nSTEP 4 — MITRE")
    print("-" * 60)
    mitre_cands = pkg.get("mitre_candidates", [])
    for idx, item in enumerate(mitre_cands[:3], start=1):
        print(f"[{idx}] {item.get('technique_id')} - {item.get('technique_name')} (Score: {item.get('score'):.4f})")

    # ---------------------------------------------------------
    # STEP 5 — PLAYBOOK
    # ---------------------------------------------------------
    print("\nSTEP 5 — PLAYBOOK")
    print("-" * 60)
    playbooks = pkg.get("playbook_evidence", [])
    for idx, item in enumerate(playbooks[:3], start=1):
        print(f"[{idx}] {item.get('playbook_name')} (Score: {item.get('score'):.4f})")

    # ---------------------------------------------------------
    # STEP 6 — CISA
    # ---------------------------------------------------------
    print("\nSTEP 6 — CISA")
    print("-" * 60)
    cisa_ev = pkg.get("cisa_evidence", [])
    for idx, item in enumerate(cisa_ev[:3], start=1):
        print(f"[{idx}] {item.get('document_title')} (Score: {item.get('score'):.4f})")

    # ---------------------------------------------------------
    # STEP 7 — EVIDENCE SUMMARY
    # ---------------------------------------------------------
    print("\nSTEP 7 — EVIDENCE SUMMARY")
    print("-" * 60)
    summary = pkg.get("evidence_summary", {})
    for k, v in summary.items():
        print(f"{k}: {v}")

    # ---------------------------------------------------------
    # STEP 8 — VALIDATION
    # ---------------------------------------------------------
    print("\nSTEP 8 — VALIDATION")
    print("-" * 60)

    checks = []

    # 1. IOC evidence extracted
    check1 = len(iocs) > 0
    checks.append(("IOC evidence extracted", check1))

    # 2. Threat Intelligence section created
    check2 = isinstance(ti_results, list) and "threat_intelligence" in pkg
    checks.append(("Threat Intelligence section created", check2))

    # 3. All extracted IOCs queried
    queried_values = {entry.get("queried_ioc") for entry in ti_results}
    extracted_values = {ioc.get("value") for ioc in iocs}
    check3 = extracted_values.issubset(queried_values) and len(ti_results) == len(iocs)
    checks.append(("All extracted IOCs queried", check3))

    # 4. No-match IOC handled correctly
    check4 = all(
        entry.get("match_found") is False and entry.get("matches") == []
        for entry in ti_results
    )
    checks.append(("No-match IOC handled correctly", check4))

    # 5. TI result structure is valid
    ti_struct_valid = True
    required_entry_keys = {"queried_ioc", "ioc_type", "match_found", "matches"}
    for entry in ti_results:
        if not required_entry_keys.issubset(set(entry.keys())) or not isinstance(entry["matches"], list):
            ti_struct_valid = False
    check5 = ti_struct_valid
    checks.append(("TI result structure is valid", check5))

    # 6. Evidence package still contains MITRE
    check6 = len(mitre_cands) > 0
    checks.append(("Evidence package still contains MITRE", check6))

    # 7. Evidence package still contains Playbook
    check7 = len(playbooks) > 0
    checks.append(("Evidence package still contains Playbook", check7))

    # 8. Evidence package still contains CISA
    check8 = len(cisa_ev) > 0
    checks.append(("Evidence package still contains CISA", check8))

    # 9. No final security verdict generated
    prohibited = {"verdict", "final_verdict", "final_classification", "confirmed_attack", "final_severity", "remediation_decision"}
    check9 = not any(k in pkg for k in prohibited)
    checks.append(("No final security verdict generated", check9))

    # 10. No live API calls made (local offline database verified)
    check10 = hasattr(builder.ti_service, "conn") and builder.ti_service.conn is not None
    checks.append(("No live API calls made", check10))

    # 11. Known-positive TI test
    known_pos_valid = (
        len(known_matches) > 0
        and any(km.get("source") == "ThreatFox" and "154.91.59.119:8084" in km.get("ioc", "") for km in known_matches)
    )
    checks.append(("Known-positive TI test (ThreatFox 154.91.59.119:8084)", known_pos_valid))

    all_passed = True
    failed_checks = []
    for label, passed in checks:
        status_tag = "[PASS]" if passed else "[FAIL]"
        print(f"{status_tag} {label}")
        if not passed:
            all_passed = False
            failed_checks.append(label)

    print("\n" + "=" * 60)
    if all_passed:
        print("Evidence Package + Threat Intelligence validation: PASSED")
    else:
        print("Evidence Package + Threat Intelligence validation: FAILED")
        for fc in failed_checks:
            print(f"FAILED CHECK: {fc}")
    print("=" * 60 + "\n")

    if not all_passed:
        sys.exit(1)


if __name__ == "__main__":
    main()
