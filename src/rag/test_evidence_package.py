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
    print("EVIDENCE PACKAGE TEST")
    print("=" * 60)

    # 1. Pipeline Execution
    pipeline = AlertRAGPipeline()
    pipeline_result = pipeline.process_alert(sample_alert)

    # 2. Evidence Package Construction
    builder = EvidencePackageBuilder()
    pkg = builder.build(pipeline_result)

    # ---------------------------------------------------------
    # STEP 1 — ALERT
    # ---------------------------------------------------------
    print("\nSTEP 1 — ALERT")
    print("-" * 60)
    meta = pkg["alert"]["alert_metadata"]
    print(f"Alert ID: {meta.get('alert_id')}")
    print(f"Severity: {meta.get('severity')}")
    print(f"Event Type: {meta.get('event_type')}")

    # ---------------------------------------------------------
    # STEP 2 — BEHAVIORAL EVIDENCE
    # ---------------------------------------------------------
    print("\nSTEP 2 — BEHAVIORAL EVIDENCE")
    print("-" * 60)
    for idx, item in enumerate(pkg["behavioral_evidence"], start=1):
        print(f"[{idx}] {item}")

    # ---------------------------------------------------------
    # STEP 3 — IOC EVIDENCE
    # ---------------------------------------------------------
    print("\nSTEP 3 — IOC EVIDENCE")
    print("-" * 60)
    for idx, ioc in enumerate(pkg["ioc_evidence"], start=1):
        print(f"[{idx}] Type: {ioc.get('type'):8} | Value: {ioc.get('value')}")

    # ---------------------------------------------------------
    # STEP 4 — MITRE CANDIDATES
    # ---------------------------------------------------------
    print("\nSTEP 4 — MITRE CANDIDATES")
    print("-" * 60)
    for idx, item in enumerate(pkg["mitre_candidates"], start=1):
        print(f"[{idx}]")
        print(f"Technique ID: {item.get('technique_id')}")
        print(f"Technique Name: {item.get('technique_name')}")
        print(f"Score: {item.get('score'):.4f}")
        print(f"Source: {item.get('source')}")
        if idx < len(pkg["mitre_candidates"]):
            print()

    # ---------------------------------------------------------
    # STEP 5 — PLAYBOOK EVIDENCE
    # ---------------------------------------------------------
    print("\nSTEP 5 — PLAYBOOK EVIDENCE")
    print("-" * 60)
    for idx, item in enumerate(pkg["playbook_evidence"], start=1):
        print(f"[{idx}]")
        print(f"Playbook: {item.get('playbook_name')}")
        print(f"Incident Type: {item.get('incident_type')}")
        print(f"Score: {item.get('score'):.4f}")
        print(f"Source: {item.get('source')}")
        if idx < len(pkg["playbook_evidence"]):
            print()

    # ---------------------------------------------------------
    # STEP 6 — CISA EVIDENCE
    # ---------------------------------------------------------
    print("\nSTEP 6 — CISA EVIDENCE")
    print("-" * 60)
    for idx, item in enumerate(pkg["cisa_evidence"], start=1):
        print(f"[{idx}]")
        print(f"Document: {item.get('document_title')}")
        print(f"Category: {item.get('category')}")
        print(f"Score: {item.get('score'):.4f}")
        print(f"Source: {item.get('source')}")
        if idx < len(pkg["cisa_evidence"]):
            print()

    # ---------------------------------------------------------
    # STEP 7 — EVIDENCE SUMMARY
    # ---------------------------------------------------------
    print("\nSTEP 7 — EVIDENCE SUMMARY")
    print("-" * 60)
    for k, v in pkg["evidence_summary"].items():
        print(f"{k}: {v}")

    # ---------------------------------------------------------
    # STEP 8 — VALIDATION
    # ---------------------------------------------------------
    print("\nSTEP 8 — VALIDATION")
    print("-" * 60)

    checks = []

    # 1. Evidence package created
    check1 = isinstance(pkg, dict) and "alert" in pkg and "mitre_candidates" in pkg
    checks.append(("Evidence package created", check1))

    # 2. Alert metadata preserved
    check2 = (
        meta.get("alert_id") == "SEC-2026-0913-001"
        and meta.get("severity") == "High"
        and meta.get("event_type") == "Brute Force Attack"
    )
    checks.append(("Alert metadata preserved", check2))

    # 3. Behavioral evidence preserved (contains original SSH failed-login observations)
    behav = pkg.get("behavioral_evidence", [])
    check3 = (
        len(behav) > 0
        and any("ssh" in b.lower() and "failed" in b.lower() for b in behav)
    )
    checks.append(("Behavioral evidence preserved", check3))

    # 4. IOC evidence preserved (contains 185.220.101.45)
    iocs = pkg.get("ioc_evidence", [])
    check4 = any(ioc.get("value") == "185.220.101.45" for ioc in iocs)
    checks.append(("IOC evidence preserved", check4))

    # 5. MITRE candidates present (contains T1110 / Brute Force)
    mitre_cands = pkg.get("mitre_candidates", [])
    has_mitre_bf = any(
        "t1110" in f"{m.get('technique_id', '')} {m.get('technique_name', '')}".lower()
        or "brute force" in f"{m.get('technique_id', '')} {m.get('technique_name', '')}".lower()
        for m in mitre_cands
    )
    check5 = len(mitre_cands) > 0 and has_mitre_bf
    checks.append(("MITRE candidates present", check5))

    # 6. Playbook evidence present (contains Brute Force Attack)
    pb_ev = pkg.get("playbook_evidence", [])
    has_pb_bf = any("brute force attack" in p.get("playbook_name", "").lower() for p in pb_ev)
    check6 = len(pb_ev) > 0 and has_pb_bf
    checks.append(("Playbook evidence present", check6))

    # 7. CISA evidence present (not empty)
    cisa_ev = pkg.get("cisa_evidence", [])
    check7 = len(cisa_ev) > 0
    checks.append(("CISA evidence present", check7))

    # 8. MITRE candidates are deduplicated by technique ID
    tech_ids = [m.get("technique_id") for m in mitre_cands]
    check8 = len(tech_ids) == len(set(tech_ids))
    checks.append(("MITRE candidates are deduplicated by technique ID", check8))

    # 9. MITRE candidates sorted by descending score
    check9 = all(
        mitre_cands[i]["score"] >= mitre_cands[i + 1]["score"]
        for i in range(len(mitre_cands) - 1)
    )
    checks.append(("MITRE candidates sorted by descending score", check9))

    # 10. Playbook evidence sorted by descending score
    check10 = all(
        pb_ev[i]["score"] >= pb_ev[i + 1]["score"]
        for i in range(len(pb_ev) - 1)
    )
    checks.append(("Playbook evidence sorted by descending score", check10))

    # 11. Evidence counts are correct
    summary = pkg.get("evidence_summary", {})
    check11 = (
        summary.get("behavioral_evidence_count") == len(behav)
        and summary.get("ioc_count") == len(iocs)
        and summary.get("mitre_candidate_count") == len(mitre_cands)
        and summary.get("playbook_evidence_count") == len(pb_ev)
        and summary.get("cisa_evidence_count") == len(cisa_ev)
    )
    checks.append(("Evidence counts are correct", check11))

    # 12. No final security verdict generated
    prohibited_keys = {
        "verdict",
        "final_verdict",
        "final_classification",
        "confirmed_attack",
        "final_severity",
        "remediation_decision",
        "malicious",
        "benign",
    }
    has_prohibited = any(k in pkg for k in prohibited_keys)
    check12 = not has_prohibited
    checks.append(("No final security verdict generated", check12))

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
        print("Evidence Package validation: PASSED")
    else:
        print("Evidence Package validation: FAILED")
        for fc in failed_checks:
            print(f"FAILED CHECK: {fc}")
    print("=" * 60 + "\n")

    if not all_passed:
        sys.exit(1)


if __name__ == "__main__":
    main()
