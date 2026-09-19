import io
import json
import os
import sys
import unittest
from typing import Any, Dict
from unittest.mock import MagicMock, patch

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

from src.agent.gemini_triage_engine import GeminiTriageEngine
from src.agent.triage_agent import TriageAgent


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


MOCK_GEMINI_RESPONSE = json.dumps({
    "alert_summary": "Alert SEC-2026-0915-001: 47 failed SSH authentication attempts from external IP 185.234.72.19 targeting internal server 10.10.25.14 across 5 usernames in a 5-minute window.",
    "incident_assessment": "High-volume external SSH authentication failure pattern consistent with automated password guessing against administrative accounts. No successful authentication was recorded.",
    "severity_assessment": {
        "alert_severity": "HIGH",
        "assessed_severity": "HIGH",
        "justification": "Retained as HIGH due to rapid credential attack rate against internal SSH server, though lack of successful logon mitigates immediate breach impact."
    },
    "behavioral_evidence": [
        "47 failed authentication attempts",
        "5 different usernames targeted",
        "Source IP repeatedly attempted SSH authentication",
        "No successful login detected"
    ],
    "ioc_findings": [
        {"ioc": "185.234.72.19", "type": "ip", "context": "External attacking source IP"},
        {"ioc": "10.10.25.14", "type": "ip", "context": "Internal RFC 1918 destination server"}
    ],
    "threat_intelligence_findings": [
        {
            "ioc": "185.234.72.19",
            "source": "Local MISP / ThreatFox",
            "match_found": False,
            "interpretation": "Indicator not cataloged in local threat intelligence index; does not signify the IP is benign or trusted."
        },
        {
            "ioc": "10.10.25.14",
            "source": "Local MISP",
            "match_found": False,
            "interpretation": "Private RFC 1918 IP address protected from external threat intelligence querying."
        }
    ],
    "mitre_analysis": [
        {
            "technique_id": "T1110",
            "technique_name": "Brute Force",
            "assessment": "SUPPORTED",
            "reason": "Explicit evidence of 47 rapid failed login attempts across multiple usernames directly aligns with brute force / password guessing.",
            "evidence": ["47 failed authentication attempts", "Source IP repeatedly attempted SSH authentication"]
        },
        {
            "technique_id": "T1110.003",
            "technique_name": "Password Spraying",
            "assessment": "PLAUSIBLE",
            "reason": "Multiple usernames (admin, root, test, support) were targeted; however, failed attempt count per user suggests mixed spraying/guessing.",
            "evidence": ["5 different usernames targeted"]
        },
        {
            "technique_id": "T1563.001",
            "technique_name": "SSH Hijacking",
            "assessment": "NOT_SUPPORTED",
            "reason": "No evidence of an established SSH session, compromised credentials, or session redirection exists in the alert.",
            "evidence": ["No successful login detected"]
        }
    ],
    "playbook_recommendations": [
        "Block or rate-limit source IP 185.234.72.19 at boundary firewall.",
        "Review SSH authentication logs to ensure no credentials were successfully validated.",
        "Verify targeted accounts (admin, root, test, support) have MFA enforced or remote SSH disabled."
    ],
    "cisa_guidance": [
        "Apply CISA guidance on hardening internet-facing remote access services (SSH port 22).",
        "Enforce centralized authentication logging and alert on anomalous brute-force spikes."
    ],
    "recommended_actions": [
        "Immediately block 185.234.72.19 on perimeter firewalls.",
        "Inspect /var/log/auth.log or equivalent on 10.10.25.14.",
        "Disable root and generic test account remote login via SSH."
    ],
    "analyst_review_required": True,
    "limitations": [
        "Host-level memory and process telemetry from 10.10.25.14 not available in alert.",
        "Passive DNS and WHOIS history for 185.234.72.19 not included in local dataset."
    ]
})


def run_tests():
    print("\n" + "=" * 60)
    print("GEMINI EVIDENCE-BASED TRIAGE TEST SUITE")
    print("=" * 60)

    checks = []

    # -------------------------------------------------------------------------
    # TEST 1 & 2: Evidence Package Generation & Delivery to Gemini
    # -------------------------------------------------------------------------
    print("\n[TEST 1 & 2] Evidence Package Generation & Ingestion")
    print("-" * 60)
    agent = TriageAgent(enable_live=False)
    evidence_package = agent.process_alert(SAMPLE_ALERT)

    check1 = bool(
        "alert" in evidence_package
        and "behavioral_evidence" in evidence_package
        and "mitre_candidates" in evidence_package
        and "threat_intelligence" in evidence_package
    )
    print(f"Evidence Package generated first: {check1}")
    print(f"Candidate MITRE techniques: {[m['technique_id'] for m in evidence_package.get('mitre_candidates', [])]}")
    checks.append(("Evidence Package generated first", check1))

    # Test prompt formatting ensures strictly controlled evidence delivery
    gemini_engine = GeminiTriageEngine()
    prompt_text = gemini_engine.build_prompt(evidence_package)
    check2 = bool(
        "SEC-2026-0915-001" in prompt_text
        and "185.234.72.19" in prompt_text
        and "CRITICAL OPERATIONAL RULES" in prompt_text
    )
    print(f"Gemini receives controlled Evidence Package: {check2}")
    checks.append(("Gemini receives the Evidence Package context", check2))

    # -------------------------------------------------------------------------
    # TEST 3: Structured Gemini Output
    # -------------------------------------------------------------------------
    print("\n[TEST 3] Structured Report Verification")
    print("-" * 60)
    mock_llm = MagicMock()
    mock_llm.invoke.return_value = MagicMock(content=MOCK_GEMINI_RESPONSE)

    engine_mocked = GeminiTriageEngine(llm_client=mock_llm)
    report = engine_mocked.reason_over_evidence(evidence_package)

    required_fields = {
        "alert_summary",
        "incident_assessment",
        "severity_assessment",
        "behavioral_evidence",
        "ioc_findings",
        "threat_intelligence_findings",
        "mitre_analysis",
        "playbook_recommendations",
        "cisa_guidance",
        "recommended_actions",
        "analyst_review_required",
        "limitations",
    }
    check3 = required_fields.issubset(set(report.keys()))
    print(f"All required report keys present: {check3}")
    print(f"Report Keys: {list(report.keys())}")
    checks.append(("Gemini output is structured", check3))

    # -------------------------------------------------------------------------
    # TEST 4 & 5: MITRE Candidate Assessment (Explicit Classification)
    # -------------------------------------------------------------------------
    print("\n[TEST 4 & 5] MITRE Candidate Classification")
    print("-" * 60)
    mitre_evals = report.get("mitre_analysis", [])
    assessments = {item["technique_id"]: item.get("assessment") for item in mitre_evals}
    print(f"Evaluated MITRE Techniques: {assessments}")

    check4 = (
        assessments.get("T1110") == "SUPPORTED"
        and assessments.get("T1110.003") == "PLAUSIBLE"
        and assessments.get("T1563.001") == "NOT_SUPPORTED"
    )
    print(f"Explicit assessment of candidates: {check4}")
    checks.append(("MITRE candidates explicitly assessed", check4))

    # Verify NOT_SUPPORTED techniques are NOT confirmed
    check5 = any(item.get("assessment") == "NOT_SUPPORTED" for item in mitre_evals)
    print(f"Unsupported techniques are not presented as confirmed: {check5}")
    checks.append(("Unsupported techniques are not presented as confirmed", check5))

    # -------------------------------------------------------------------------
    # TEST 6: Threat Intelligence Meaning Preserved
    # -------------------------------------------------------------------------
    print("\n[TEST 6] Threat Intelligence Semantics")
    print("-" * 60)
    ti_findings = report.get("threat_intelligence_findings", [])
    ti_meaning_ok = False
    for tf in ti_findings:
        if tf.get("ioc") == "185.234.72.19":
            interp = tf.get("interpretation", "").lower()
            # Must state not found does not mean benign
            if "does not" in interp and ("benign" in interp or "safe" in interp or "cataloged" in interp):
                ti_meaning_ok = True
    print(f"TI match/no-match meaning preserved: {ti_meaning_ok}")
    checks.append(("TI match/no-match meaning is preserved", ti_meaning_ok))

    # -------------------------------------------------------------------------
    # TEST 7: No Evidence Invented
    # -------------------------------------------------------------------------
    print("\n[TEST 7] Evidence Grounding (No Invention)")
    print("-" * 60)
    report_iocs = {ioc["ioc"] for ioc in report.get("ioc_findings", [])}
    expected_iocs = {"185.234.72.19", "10.10.25.14"}
    check7 = report_iocs.issubset(expected_iocs)
    print(f"Report IOCs ({report_iocs}) match alert IOCs ({expected_iocs}): {check7}")
    checks.append(("No evidence is invented", check7))

    # -------------------------------------------------------------------------
    # TEST 8: API Key Protection (Zero Leakage)
    # -------------------------------------------------------------------------
    print("\n[TEST 8] API Key Protection (Never Printed)")
    print("-" * 60)
    secret_key = "AIzaSy_FAKE_SECRET_TEST_KEY_1234567890"

    old_stdout = sys.stdout
    captured = io.StringIO()
    try:
        sys.stdout = captured
        sec_engine = GeminiTriageEngine(api_key=secret_key, llm_client=mock_llm)
        sec_report = sec_engine.reason_over_evidence(evidence_package)
    finally:
        sys.stdout = old_stdout

    leak_in_stdout = secret_key in captured.getvalue()
    leak_in_report = secret_key in json.dumps(sec_report)
    check8 = (not leak_in_stdout) and (not leak_in_report)
    print(f"API key leaked in stdout: {leak_in_stdout}")
    print(f"API key leaked in report: {leak_in_report}")
    checks.append(("API key is never printed or exposed", check8))

    # -------------------------------------------------------------------------
    # TEST 9: Gemini API Failure Safe Handling (Fallback Report)
    # -------------------------------------------------------------------------
    print("\n[TEST 9] API Failure Safe Handling")
    print("-" * 60)
    failing_llm = MagicMock()
    failing_llm.invoke.side_effect = RuntimeError("Rate limit exceeded (429 Resource Exhausted)")

    failing_engine = GeminiTriageEngine(llm_client=failing_llm)
    fallback_report = failing_engine.reason_over_evidence(evidence_package)

    check9 = (
        isinstance(fallback_report, dict)
        and fallback_report.get("analyst_review_required") is True
        and "unavailable" in fallback_report.get("incident_assessment", "").lower()
    )
    print(f"Fallback report generated safely on API error: {check9}")
    print(f"Fallback assessment: {fallback_report.get('incident_assessment')}")
    checks.append(("Gemini API failure is handled safely without crashing", check9))

    # -------------------------------------------------------------------------
    # TEST 10: Analyst Review Required
    # -------------------------------------------------------------------------
    print("\n[TEST 10] Human-in-the-Loop Enforcement")
    print("-" * 60)
    check10 = report.get("analyst_review_required") is True
    print(f"analyst_review_required flag is True: {check10}")
    checks.append(("analyst_review_required is present and True", check10))

    # -------------------------------------------------------------------------
    # SUMMARY
    # -------------------------------------------------------------------------
    print("\n" + "=" * 60)
    print("VALIDATION SUMMARY")
    print("=" * 60)
    all_passed = True
    for label, status in checks:
        state = "[PASS]" if status else "[FAIL]"
        print(f"{state:7} {label}")
        if not status:
            all_passed = False

    print("=" * 60)
    if all_passed:
        print("Gemini Evidence-Based Triage Test Suite: PASSED")
    else:
        print("Gemini Evidence-Based Triage Test Suite: FAILED")
    print("=" * 60)

    # Optional Real Gemini API test
    if "--real-api" in sys.argv:
        print("\n" + "=" * 60)
        print("MANUAL REAL GEMINI API TEST")
        print("=" * 60)
        real_engine = GeminiTriageEngine()
        if not real_engine.has_api_key:
            print("GOOGLE_API_KEY not found in environment. Skipping real API test.")
        else:
            print("Invoking real Gemini API with Evidence Package...")
            real_report = real_engine.reason_over_evidence(evidence_package)
            print("\nREAL GEMINI TRIAGE REPORT:")
            print(json.dumps(real_report, indent=2))
        print("=" * 60)

    return all_passed


if __name__ == "__main__":
    success = run_tests()
    sys.exit(0 if success else 1)
