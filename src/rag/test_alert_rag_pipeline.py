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
    print("ALERT → RAG PIPELINE TEST")
    print("=" * 60)

    # Initialize pipeline
    pipeline = AlertRAGPipeline()

    # Process complete alert
    result = pipeline.process_alert(sample_alert)

    parsed_alert = result["parsed_alert"]
    rag_query = result["rag_query"]
    rag_results = result["rag_results"]

    # ---------------------------------------------------------
    # STEP 1 — PARSED ALERT
    # ---------------------------------------------------------
    print("\nSTEP 1 — PARSED ALERT")
    print("-" * 60)
    metadata = parsed_alert.get("alert_metadata", {})
    net_ctx = parsed_alert.get("network_context", {})
    ctx = parsed_alert.get("context", {})
    behav_ev = parsed_alert.get("behavioral_evidence", [])
    ioc_ev = parsed_alert.get("ioc_evidence", [])

    print(f"Alert ID: {metadata.get('alert_id')}")
    print(f"Severity: {metadata.get('severity')}")
    print(f"Event Type: {metadata.get('event_type')}")
    print(f"Source IP: {net_ctx.get('source_ip')}")
    print(f"Destination IP: {net_ctx.get('destination_ip')}")
    print(f"Behavioral Evidence count: {len(behav_ev)}")
    print(f"IOC Evidence count: {len(ioc_ev)}")
    print(f"Target Service: {ctx.get('target_service')}")

    # ---------------------------------------------------------
    # STEP 2 — GENERATED RAG QUERY
    # ---------------------------------------------------------
    print("\nSTEP 2 — GENERATED RAG QUERY")
    print("-" * 60)
    print(rag_query)

    # ---------------------------------------------------------
    # STEP 3 — MITRE RAG RESULTS
    # ---------------------------------------------------------
    print("\nSTEP 3 — MITRE RAG RESULTS")
    print("-" * 60)
    mitre_results = rag_results.get("mitre", [])
    for idx, item in enumerate(mitre_results[:5], start=1):
        print(f"[{idx}]")
        print(f"Technique ID: {item.get('technique_id')}")
        print(f"Technique Name: {item.get('technique_name')}")
        print(f"Score: {item.get('score'):.4f}")
        print(f"Source: {item.get('source')}")
        if idx < min(5, len(mitre_results)):
            print()

    # ---------------------------------------------------------
    # STEP 4 — PLAYBOOK RAG RESULTS
    # ---------------------------------------------------------
    print("\nSTEP 4 — PLAYBOOK RAG RESULTS")
    print("-" * 60)
    playbook_results = rag_results.get("playbooks", [])
    for idx, item in enumerate(playbook_results[:5], start=1):
        print(f"[{idx}]")
        print(f"Playbook: {item.get('playbook_name')}")
        print(f"Incident Type: {item.get('incident_type')}")
        print(f"Score: {item.get('score'):.4f}")
        print(f"Source: {item.get('source')}")
        if idx < min(5, len(playbook_results)):
            print()

    # ---------------------------------------------------------
    # STEP 5 — CISA RAG RESULTS
    # ---------------------------------------------------------
    print("\nSTEP 5 — CISA RAG RESULTS")
    print("-" * 60)
    cisa_results = rag_results.get("cisa", [])
    for idx, item in enumerate(cisa_results[:5], start=1):
        print(f"[{idx}]")
        print(f"Document: {item.get('document_title')}")
        print(f"Category: {item.get('category')}")
        print(f"Score: {item.get('score'):.4f}")
        print(f"Source: {item.get('source')}")
        if idx < min(5, len(cisa_results)):
            print()

    # ---------------------------------------------------------
    # STEP 6 — VALIDATION
    # ---------------------------------------------------------
    print("\nSTEP 6 — VALIDATION")
    print("-" * 60)

    checks = []

    # 1. Alert parser produced structured output
    check1 = bool(
        isinstance(parsed_alert, dict)
        and metadata.get("alert_id") == "SEC-2026-0913-001"
        and net_ctx.get("source_ip") == "185.220.101.45"
    )
    checks.append(("Alert parser produced structured output", check1))

    # 2. Behavioral evidence passed into RAG query
    check2 = bool(
        len(behav_ev) > 0
        and all(ev.rstrip(".") in rag_query for ev in behav_ev)
    )
    checks.append(("Behavioral evidence passed into RAG query", check2))

    # 3. RAG query is not empty
    check3 = bool(rag_query and rag_query.strip())
    checks.append(("RAG query is not empty", check3))

    # 4. MITRE results returned
    check4 = len(mitre_results) > 0
    checks.append(("MITRE results returned", check4))

    # 5. Playbook results returned
    check5 = len(playbook_results) > 0
    checks.append(("Playbook results returned", check5))

    # 6. CISA results returned
    check6 = len(cisa_results) > 0
    checks.append(("CISA results returned", check6))

    # 7. MITRE contains relevant brute-force technique
    brute_force_concepts = ["t1110", "brute force", "password guessing", "password spraying"]
    mitre_has_brute_force = any(
        any(concept in f"{m.get('technique_id', '')} {m.get('technique_name', '')}".lower() for concept in brute_force_concepts)
        for m in mitre_results
    )
    checks.append(("MITRE contains relevant brute-force technique", mitre_has_brute_force))

    # 8. Playbook contains Brute Force Attack
    playbook_has_brute_force = any(
        "brute force attack" in item.get("playbook_name", "").lower()
        for item in playbook_results
    )
    checks.append(("Playbook contains Brute Force Attack", playbook_has_brute_force))

    # 9. CISA returned evidence
    cisa_has_evidence = len(cisa_results) > 0
    checks.append(("CISA returned evidence", cisa_has_evidence))

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
        print("Alert → RAG pipeline validation: PASSED")
    else:
        print("Alert → RAG pipeline validation: FAILED")
        for fc in failed_checks:
            print(f"FAILED CHECK: {fc}")
    print("=" * 60 + "\n")

    if not all_passed:
        sys.exit(1)


if __name__ == "__main__":
    main()
