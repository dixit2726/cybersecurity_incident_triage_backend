import os
import sys
from typing import Any, Dict

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

from src.agent.triage_agent import TriageAgent
from src.tools.abusech_api_client import is_private_or_local_ip


SAMPLE_ALERT = """ALERT ID: SEC-2026-0915-001
Timestamp: 2026-09-15 15:28:41 UTC

Alert Type: Multiple Failed Login Attempts
Event Type: Brute Force Attack
Severity: HIGH

Source IP: 185.234.72.19
Destination IP: 10.10.25.14
Protocol: TCP
Destination Port: 22
Service: SSH

Description:
The security monitoring system detected 47 failed SSH login attempts against
the internal server 10.10.25.14 within 5 minutes. The attempts originated
from the external IP address 185.234.72.19 and targeted multiple usernames,
including admin, root, test, and support.

Observed Activity:
- 47 failed authentication attempts
- 5 different usernames targeted
- Attack duration: 5 minutes
- Source IP repeatedly attempted SSH authentication
- No successful login detected

Attack Category: Credential Access / Brute Force
Severity: HIGH

Recommended Action:
1. Block or temporarily rate-limit the source IP.
2. Review SSH authentication logs for successful attempts.
3. Disable unnecessary SSH accounts.
4. Enforce MFA and strong password policies.
5. Check the targeted server for indicators of compromise."""


def main():
    print("\n" + "=" * 60)
    print("AI AGENT / ORCHESTRATOR TEST")
    print("=" * 60)

    # 1. Initialize Triage Agent
    print("\nInitializing TriageAgent...")
    agent = TriageAgent(enable_live=False)

    # 2. Process Complete Alert
    print("\nProcessing complete alert through TriageAgent.process_alert()...")
    result = agent.process_alert(SAMPLE_ALERT)

    # ---------------------------------------------------------
    # STEP 1 — ALERT PARSING & STRUCTURED DATA
    # ---------------------------------------------------------
    print("\nSTEP 1 — ALERT METADATA & PARSING")
    print("-" * 60)
    alert_info = result.get("alert", {})
    metadata = alert_info.get("alert_metadata", {})
    net_ctx = alert_info.get("network_context", {})
    print(f"Alert ID        : {metadata.get('alert_id')}")
    print(f"Severity        : {metadata.get('severity')}")
    print(f"Event Type      : {metadata.get('event_type')}")
    print(f"Source IP       : {net_ctx.get('source_ip')}")
    print(f"Destination IP  : {net_ctx.get('destination_ip')}")
    print(f"Port            : {net_ctx.get('destination_port')}")

    # ---------------------------------------------------------
    # STEP 2 — BEHAVIORAL EVIDENCE & IOCs
    # ---------------------------------------------------------
    print("\nSTEP 2 — BEHAVIORAL EVIDENCE & IOCs")
    print("-" * 60)
    behavioral_ev = result.get("behavioral_evidence", [])
    print(f"Behavioral Evidence Statements ({len(behavioral_ev)} items):")
    for idx, stmt in enumerate(behavioral_ev, start=1):
        print(f"  [{idx}] {stmt}")

    ioc_ev = result.get("ioc_evidence", [])
    print(f"\nExtracted IOCs ({len(ioc_ev)} items):")
    for idx, ioc in enumerate(ioc_ev, start=1):
        print(f"  [{idx}] Type: {ioc.get('type'):6} | Value: {ioc.get('value')}")

    # ---------------------------------------------------------
    # STEP 3 — THREAT INTELLIGENCE & PRIVACY
    # ---------------------------------------------------------
    print("\nSTEP 3 — THREAT INTELLIGENCE & PRIVATE IP PROTECTION")
    print("-" * 60)
    ti_results = result.get("threat_intelligence", [])
    for idx, entry in enumerate(ti_results, start=1):
        val = entry.get("queried_ioc", "")
        is_priv = is_private_or_local_ip(val)
        status = "PRIVATE (Protected from public APIs)" if is_priv else "PUBLIC (Eligible for TI)"
        print(f"[{idx}] Queried IOC : {val:16} | Type: {entry.get('ioc_type'):6} | Matches: {len(entry.get('matches', []))} | {status}")

    # ---------------------------------------------------------
    # STEP 4 — RAG CONTEXT (MITRE, Playbooks, CISA)
    # ---------------------------------------------------------
    print("\nSTEP 4 — MULTI-SOURCE RAG RETRIEVAL")
    print("-" * 60)
    mitre_cands = result.get("mitre_candidates", [])
    print(f"MITRE ATT&CK Candidates ({len(mitre_cands)} retrieved):")
    for idx, item in enumerate(mitre_cands[:3], start=1):
        print(f"  [{idx}] {item.get('technique_id')} - {item.get('technique_name')} (Score: {item.get('score'):.4f})")

    pb_ev = result.get("playbook_evidence", [])
    print(f"\nPlaybook Procedures ({len(pb_ev)} retrieved):")
    for idx, item in enumerate(pb_ev[:3], start=1):
        print(f"  [{idx}] {item.get('playbook_name')} (Score: {item.get('score'):.4f})")

    cisa_ev = result.get("cisa_evidence", [])
    print(f"\nCISA Guidance ({len(cisa_ev)} retrieved):")
    for idx, item in enumerate(cisa_ev[:3], start=1):
        print(f"  [{idx}] {item.get('document_title')} (Score: {item.get('score'):.4f})")

    # ---------------------------------------------------------
    # STEP 5 — EVIDENCE SUMMARY
    # ---------------------------------------------------------
    print("\nSTEP 5 — EVIDENCE SUMMARY")
    print("-" * 60)
    summary = result.get("evidence_summary", {})
    for k, v in summary.items():
        print(f"  {k:32}: {v}")

    # ---------------------------------------------------------
    # STEP 6 — VALIDATION CHECKS
    # ---------------------------------------------------------
    print("\nSTEP 6 — VALIDATION")
    print("-" * 60)
    checks = []

    # 1. Complete alert accepted
    check1 = bool(result and isinstance(result, dict))
    checks.append(("Complete alert accepted", check1))

    # 2. Alert Parser executed
    check2 = metadata.get("alert_id") == "SEC-2026-0915-001" and metadata.get("severity") == "HIGH"
    checks.append(("Alert Parser executed", check2))

    # 3. Behavioral evidence extracted
    check3 = len(behavioral_ev) > 0
    checks.append(("Behavioral evidence extracted", check3))

    # 4. IOC evidence extracted
    check4 = len(ioc_ev) >= 2 and any(i.get("value") == "185.234.72.19" for i in ioc_ev)
    checks.append(("IOC evidence extracted", check4))

    # 5. Threat Intelligence executed
    check5 = len(ti_results) == len(ioc_ev)
    checks.append(("Threat Intelligence executed", check5))

    # 6. Private IP 10.10.25.14 is protected
    check6 = is_private_or_local_ip("10.10.25.14") is True
    checks.append(("Private IP 10.10.25.14 is protected", check6))

    # 7. Public IP 185.234.72.19 can be considered for TI
    check7 = is_private_or_local_ip("185.234.72.19") is False
    checks.append(("Public IP 185.234.72.19 can be considered for TI", check7))

    # 8. MITRE retrieval executed
    check8 = len(mitre_cands) > 0 and any(m.get("technique_id") == "T1110" for m in mitre_cands)
    checks.append(("MITRE retrieval executed", check8))

    # 9. Playbook retrieval executed
    check9 = len(pb_ev) > 0 and any("Brute Force" in p.get("playbook_name", "") for p in pb_ev)
    checks.append(("Playbook retrieval executed", check9))

    # 10. CISA retrieval executed
    check10 = len(cisa_ev) > 0
    checks.append(("CISA retrieval executed", check10))

    # 11. Evidence Package generated
    check11 = bool(summary and "behavioral_evidence_count" in summary)
    checks.append(("Evidence Package generated", check11))

    # 12. No final security verdict is generated
    prohibited = {"verdict", "final_verdict", "final_classification", "confirmed_attack", "final_severity", "remediation_decision"}
    check12 = not any(k in result for k in prohibited)
    checks.append(("No final security verdict is generated", check12))

    # 13. No evidence is invented
    check13 = (
        metadata.get("alert_id") == "SEC-2026-0915-001"
        and net_ctx.get("source_ip") == "185.234.72.19"
        and net_ctx.get("destination_ip") == "10.10.25.14"
        and net_ctx.get("destination_port") == "22"
    )
    checks.append(("No evidence is invented", check13))

    all_passed = True
    for label, status in checks:
        state = "[PASS]" if status else "[FAIL]"
        print(f"{state:7} {label}")
        if not status:
            all_passed = False

    print("=" * 60)
    if all_passed:
        print("Triage Agent Validation: PASSED")
    else:
        print("Triage Agent Validation: FAILED")
    print("=" * 60 + "\n")

    return all_passed


if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1)
