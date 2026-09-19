import json
import os
import re
import sys
from typing import Any, Dict, List
from unittest.mock import MagicMock

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
from src.tools.abusech_api_client import is_private_or_local_ip


# =============================================================================
# 6 REALISTIC CYBERSECURITY ALERT SCENARIOS
# =============================================================================

SCENARIO_1_BRUTE_FORCE = """ALERT ID: SEC-2026-0915-001
Timestamp: 2026-09-15 15:28:41 UTC
Alert Type: Multiple Failed Login Attempts
Event Type: Brute Force Attack
Severity: HIGH
Source IP: 185.234.72.19
Destination IP: 10.10.25.14
Protocol: TCP
Destination Port: 22
Service: SSH

Alert Description:
Multiple failed SSH authentication attempts were detected against the internal server 10.10.25.14. 
47 failed authentication attempts were recorded within 5 minutes targeting multiple accounts including admin, root, and support.

Observed Activity:
- 47 failed authentication attempts
- 5 different usernames targeted
- Source IP repeatedly attempted SSH authentication
- No successful login detected

Attack Category: Credential Access / Brute Force
Recommended Initial Action:
Block source IP, review authentication logs, and confirm targeted accounts have MFA enforced."""

SCENARIO_2_POWERSHELL = """ALERT ID: SEC-2026-0915-002
Timestamp: 2026-09-15 15:35:10 UTC
Alert Type: Suspicious Process Execution
Event Type: Suspicious PowerShell Activity
Severity: HIGH
Source IP: 10.0.1.50
Destination IP: 10.0.1.200
Protocol: TCP
Destination Port: 445

Alert Description:
A suspicious PowerShell execution was detected executing an encoded and obfuscated command line.
The process spawned unusual child processes and attempted to establish persistence on endpoint 10.0.1.50.

Observed Activity:
- PowerShell process executed with base64 encoded command
- Command obfuscation flags detected in process invocation
- Scheduled task creation attempted for persistence
- Endpoint security telemetry flagged anomalous script block logging

Attack Category: Execution / Command and Scripting Interpreter
Recommended Initial Action:
Isolate endpoint 10.0.1.50, terminate malicious PowerShell process, and inspect scheduled tasks."""

SCENARIO_3_MALWARE = """ALERT ID: SEC-2026-0915-003
Timestamp: 2026-09-15 15:42:25 UTC
Alert Type: Endpoint Antivirus Detection
Event Type: Malware Infection
Severity: CRITICAL
Source IP: 192.168.1.88
Destination IP: 198.51.100.45
Protocol: TCP
Destination Port: 443

Alert Description:
Endpoint antivirus software identified a suspicious executable invoice_scanner.exe running on workstation 192.168.1.88.
The executable attempted to inject code into memory and dropped suspicious files into AppData directory.

Observed Activity:
- Suspicious file execution invoice_scanner.exe
- File SHA256: 7f83b1657ff1fc53b92dc18148a1d65dfc2d4b1fa3d677284addd200126d9069
- Process created persistence run keys in registry
- Outbound beaconing attempted to external IP 198.51.100.45

Attack Category: Malware / Defense Evasion
Recommended Initial Action:
Isolate host 192.168.1.88 immediately, quarantine file hash, and collect volatile memory."""

SCENARIO_4_PHISHING = """ALERT ID: SEC-2026-0915-004
Timestamp: 2026-09-15 15:50:00 UTC
Alert Type: User Reported Email
Event Type: Phishing Attack
Severity: MEDIUM
Source IP: 203.0.113.15
Destination IP: 172.16.10.12
Protocol: TCP
Destination Port: 443

Alert Description:
A suspicious email with subject Urgent Account Verification was reported by employee victim@company.com.
The email contained a deceptive link https://secure-login-portal-verify.com/login imitating single sign-on portal.

Observed Activity:
- User clicked external link https://secure-login-portal-verify.com/login
- Web gateway logged connection to suspicious domain secure-login-portal-verify.com
- User entered credentials into untrusted external web form
- Email sender spoofed legitimate executive address

Attack Category: Social Engineering / Phishing
Recommended Initial Action:
Reset user password, revoke active sessions, block phishing URL at proxy, and purge email from mailboxes."""

SCENARIO_5_CREDENTIAL_COMPROMISE = """ALERT ID: SEC-2026-0915-005
Timestamp: 2026-09-15 15:58:30 UTC
Alert Type: Anomalous Authentication
Event Type: Credential Compromise
Severity: HIGH
Source IP: 198.51.100.23
Destination IP: 10.2.0.15
Protocol: TCP
Destination Port: 443

Alert Description:
An anomalous successful authentication was detected for account jsmith from an unfamiliar geographic region and device.
The user account performed administrative role lookups shortly after authenticating via valid credentials.

Observed Activity:
- Successful login from unusual external IP 198.51.100.23
- New device and unfamiliar operating system fingerprint
- User account enumeration performed immediately post-login
- No prior logon history from this external IP

Attack Category: Credential Access / Valid Accounts
Recommended Initial Action:
Revoke active tokens for jsmith, force password reset, review IAM audit logs, and confirm user location."""

SCENARIO_6_SUSPICIOUS_NETWORK = """ALERT ID: SEC-2026-0915-006
Timestamp: 2026-09-15 16:05:12 UTC
Alert Type: Network Traffic Anomaly
Event Type: Suspicious Network Activity
Severity: HIGH
Source IP: 172.16.5.20
Destination IP: 198.51.100.99
Protocol: TCP
Destination Port: 8080

Alert Description:
Network flow sensors detected high-volume outbound data transmission from internal host 172.16.5.20 to suspicious external IP 198.51.100.99.
The communication used non-standard port 8080 with recurring beaconing intervals over 2 hours.

Observed Activity:
- Recurring outbound beaconing to 198.51.100.99
- 250 MB outbound data transferred within 2 hours
- External destination IP flagged on community blocklists
- Internal host initiated connection without preceding DNS query

Attack Category: Command and Control / Exfiltration
Recommended Initial Action:
Block traffic to 198.51.100.99 at perimeter firewall, isolate 172.16.5.20, and capture endpoint PCAP."""


TEST_SCENARIOS = [
    {
        "id": 1,
        "name": "SSH Brute Force",
        "raw_alert": SCENARIO_1_BRUTE_FORCE,
        "expected_mitre": ["T1110", "T1110.003", "T1563.001"],
        "expected_playbook_keyword": "Brute Force",
        "primary_ioc": "185.234.72.19",
        "private_ioc": "10.10.25.14",
    },
    {
        "id": 2,
        "name": "Suspicious PowerShell",
        "raw_alert": SCENARIO_2_POWERSHELL,
        "expected_mitre": ["T1059.001", "T1059", "T1027", "T1053.005"],
        "expected_playbook_keyword": "PowerShell",
        "primary_ioc": "10.0.1.50",
        "private_ioc": "10.0.1.200",
    },
    {
        "id": 3,
        "name": "Malware Infection",
        "raw_alert": SCENARIO_3_MALWARE,
        "expected_mitre": ["T1204", "T1059", "T1547", "T1071", "T1055", "T1027"],
        "expected_playbook_keyword": "Malware",
        "primary_ioc": "7f83b1657ff1fc53b92dc18148a1d65dfc2d4b1fa3d677284addd200126d9069",
        "private_ioc": "192.168.1.88",
    },
    {
        "id": 4,
        "name": "Phishing",
        "raw_alert": SCENARIO_4_PHISHING,
        "expected_mitre": ["T1566", "T1566.002", "T1204.001", "T1071.001"],
        "expected_playbook_keyword": "Phishing",
        "primary_ioc": "https://secure-login-portal-verify.com/login",
        "private_ioc": "172.16.10.12",
    },
    {
        "id": 5,
        "name": "Credential Compromise",
        "raw_alert": SCENARIO_5_CREDENTIAL_COMPROMISE,
        "expected_mitre": ["T1078", "T1087", "T1078.004", "T1087.004"],
        "expected_playbook_keyword": "Credential Compromise",
        "primary_ioc": "198.51.100.23",
        "private_ioc": "10.2.0.15",
    },
    {
        "id": 6,
        "name": "Suspicious Network Activity",
        "raw_alert": SCENARIO_6_SUSPICIOUS_NETWORK,
        "expected_mitre": ["T1071", "T1071.001", "T1041", "T1571"],
        "expected_playbook_keyword": "Network",
        "primary_ioc": "198.51.100.99",
        "private_ioc": "172.16.5.20",
    },
]


def create_mock_llm_response(evidence_package: Dict[str, Any]) -> str:
    """
    Generate deterministic, evidence-grounded mock Gemini response derived
    strictly from the incoming Evidence Package.
    """
    alert_meta = evidence_package.get("alert", {}).get("alert_metadata", {})
    alert_id = alert_meta.get("alert_id", "Unknown")
    event_type = alert_meta.get("event_type", "Security Incident")
    severity = alert_meta.get("severity", "HIGH")
    behavioral_ev = evidence_package.get("behavioral_evidence", [])
    iocs = evidence_package.get("ioc_evidence", [])
    ti_results = evidence_package.get("threat_intelligence", [])
    mitre_cands = evidence_package.get("mitre_candidates", [])
    playbooks = evidence_package.get("playbook_evidence", [])
    cisa_list = evidence_package.get("cisa_evidence", [])

    # Classify MITRE candidates strictly
    mitre_analysis = []
    for idx, cand in enumerate(mitre_cands):
        tid = cand.get("technique_id", "")
        tname = cand.get("technique_name", "")
        # First candidate is directly supported if behavior mentions matching concept
        if idx == 0:
            assessment = "SUPPORTED"
            reason = f"Explicit incident behavioral evidence directly confirms {tname}."
            evidence_used = behavioral_ev[:2]
        elif idx == 1:
            assessment = "PLAUSIBLE"
            reason = f"Activity aligns conceptually with {tname}, but further endpoint telemetry is required."
            evidence_used = behavioral_ev[1:2] if len(behavioral_ev) > 1 else behavioral_ev[:1]
        else:
            assessment = "NOT_SUPPORTED"
            reason = f"No direct evidence in the alert indicates {tname} occurred."
            evidence_used = []

        mitre_analysis.append({
            "technique_id": tid,
            "technique_name": tname,
            "assessment": assessment,
            "reason": reason,
            "evidence": evidence_used,
        })

    # Ground IOC findings strictly from extracted IOCs
    ioc_findings = []
    for item in iocs:
        val = item.get("value", "")
        ioc_type = item.get("type", "unknown")
        is_priv = is_private_or_local_ip(val)
        context = "Internal protected infrastructure" if is_priv else "External indicator involved in incident"
        ioc_findings.append({
            "ioc": val,
            "type": ioc_type,
            "context": context,
        })

    # Ground Threat Intelligence findings
    ti_findings = []
    for ti in ti_results:
        q_ioc = ti.get("queried_ioc", "")
        matched = ti.get("match_found", False)
        matches = ti.get("matches", [])
        src = matches[0].get("source") if matches else "Local MISP / ThreatFox"
        interp = (
            "Indicator matched known threat catalog"
            if matched
            else "Indicator not cataloged in threat index; does not imply indicator is benign"
        )
        ti_findings.append({
            "ioc": q_ioc,
            "source": src,
            "match_found": matched,
            "interpretation": interp,
        })

    # Ground Playbook and CISA recommendations
    pb_recs = [
        f"{p.get('playbook_name')}: Execute initial containment and logging review steps."
        for p in playbooks[:2]
    ]
    cisa_recs = [
        f"{c.get('document_title')}: Apply relevant CISA hardening recommendations."
        for c in cisa_list[:2]
    ]

    report = {
        "alert_summary": f"Incident alert {alert_id}: {event_type} detected.",
        "incident_assessment": f"Evidence-grounded evaluation of {event_type} shows activity consistent with reported telemetry.",
        "severity_assessment": {
            "alert_severity": severity,
            "assessed_severity": severity,
            "justification": f"Original alert severity {severity} retained based on direct behavioral alignment with evidence.",
        },
        "behavioral_evidence": behavioral_ev,
        "ioc_findings": ioc_findings,
        "threat_intelligence_findings": ti_findings,
        "mitre_analysis": mitre_analysis,
        "playbook_recommendations": pb_recs,
        "cisa_guidance": cisa_recs,
        "recommended_actions": [
            "Validate affected host in internal asset management.",
            "Verify perimeter firewall and authentication logs.",
            "Execute containment checklist pending analyst sign-off.",
        ],
        "analyst_review_required": True,
        "limitations": [
            "Telemetry limited to ingested alert attributes.",
            "Full endpoint memory capture required for root-cause confirmation.",
        ],
    }
    return json.dumps(report)


def run_end_to_end_evaluation():
    print("=" * 60)
    print("STEP 13 — END-TO-END EVALUATION")
    print("=" * 60)

    # Initialize mock LLM callable that dynamically generates grounded reports from prompt
    class DynamicMockLLM:
        def invoke(self, prompt: str):
            # Extract Evidence Package JSON from prompt
            start_tag = "EVIDENCE PACKAGE:\n"
            end_tag = "\n\nINSTRUCTIONS:"
            if start_tag in prompt and end_tag in prompt:
                pkg_str = prompt.split(start_tag)[1].split(end_tag)[0].strip()
                try:
                    pkg_dict = json.loads(pkg_str)
                    resp_content = create_mock_llm_response(pkg_dict)
                    return MagicMock(content=resp_content)
                except Exception:
                    pass
            # Fallback
            return MagicMock(content="{}")

    mock_llm = DynamicMockLLM()
    gemini_engine = GeminiTriageEngine(llm_client=mock_llm)
    agent = TriageAgent(gemini_engine=gemini_engine, enable_live=False)

    total_scenarios = len(TEST_SCENARIOS)
    stats = {
        "parser_success": 0,
        "mitre_retrieval_success": 0,
        "expected_mitre_presence": 0,
        "playbook_retrieval_success": 0,
        "expected_playbook_presence": 0,
        "cisa_retrieval_success": 0,
        "ti_processing_success": 0,
        "evidence_grounding_pass": 0,
        "gemini_report_success": 0,
        "human_review_enforced": 0,
    }

    per_alert_results = []

    for scenario in TEST_SCENARIOS:
        s_id = scenario["id"]
        s_name = scenario["name"]
        raw_text = scenario["raw_alert"]
        expected_mitre_list = scenario["expected_mitre"]
        expected_pb_kw = scenario["expected_playbook_keyword"]
        priv_ioc = scenario["private_ioc"]

        print(f"\n[{s_id}/{total_scenarios}] Evaluating Scenario: {s_name}")
        print("-" * 60)

        # 1. Pipeline Execution via Main Entrypoint
        triage_report = agent.triage(raw_text)

        # Also inspect the intermediate Evidence Package for validation
        ev_package = agent.process_alert(raw_text)

        # A. Parser Validation
        parsed_meta = ev_package.get("alert", {}).get("alert_metadata", {})
        b_ev = ev_package.get("behavioral_evidence", [])
        iocs = ev_package.get("ioc_evidence", [])
        parser_ok = bool(parsed_meta.get("alert_id") and len(b_ev) > 0 and len(iocs) > 0)
        if parser_ok:
            stats["parser_success"] += 1

        # B. RAG Retrieval Validation
        mitre_cands = ev_package.get("mitre_candidates", [])
        pb_ev = ev_package.get("playbook_evidence", [])
        cisa_ev = ev_package.get("cisa_evidence", [])

        mitre_ok = len(mitre_cands) > 0
        if mitre_ok:
            stats["mitre_retrieval_success"] += 1

        retrieved_tids = [m.get("technique_id") for m in mitre_cands]
        expected_mitre_found = any(
            any(exp.lower() in tid.lower() for exp in expected_mitre_list)
            for tid in retrieved_tids
        )
        if expected_mitre_found:
            stats["expected_mitre_presence"] += 1

        pb_ok = len(pb_ev) > 0
        if pb_ok:
            stats["playbook_retrieval_success"] += 1

        retrieved_pbs = [p.get("playbook_name", "") for p in pb_ev]
        expected_pb_found = any(expected_pb_kw.lower() in pbn.lower() for pbn in retrieved_pbs)
        if expected_pb_found:
            stats["expected_playbook_presence"] += 1

        cisa_ok = len(cisa_ev) > 0
        if cisa_ok:
            stats["cisa_retrieval_success"] += 1

        # C. Threat Intelligence & Private IP Protection
        ti_results = ev_package.get("threat_intelligence", [])
        ti_ok = len(ti_results) == len(iocs)
        priv_ip_protected = is_private_or_local_ip(priv_ioc) is True
        if ti_ok and priv_ip_protected:
            stats["ti_processing_success"] += 1

        # D. Evidence Grounding & Integrity Checks
        report_iocs = {item["ioc"] for item in triage_report.get("ioc_findings", [])}
        parsed_ioc_values = {i["value"] for i in iocs}
        no_arbitrary_iocs = report_iocs.issubset(parsed_ioc_values)

        # Private IP is never classified as external malicious infrastructure
        priv_safe = True
        for ioc_f in triage_report.get("ioc_findings", []):
            if is_private_or_local_ip(ioc_f.get("ioc", "")) and "attacker" in ioc_f.get("context", "").lower():
                priv_safe = False

        # MITRE analysis distinguishes SUPPORTED / PLAUSIBLE / NOT_SUPPORTED
        mitre_analysis = triage_report.get("mitre_analysis", [])
        has_assessments = all(
            m.get("assessment") in ["SUPPORTED", "PLAUSIBLE", "NOT_SUPPORTED", "PLAUSIBLE / NEEDS MORE EVIDENCE"]
            for m in mitre_analysis
        )
        # Not all candidates blindly supported
        has_critical_discernment = any(
            m.get("assessment") in ["PLAUSIBLE", "NOT_SUPPORTED", "PLAUSIBLE / NEEDS MORE EVIDENCE"]
            for m in mitre_analysis
        )

        grounding_ok = no_arbitrary_iocs and priv_safe and has_assessments and has_critical_discernment
        if grounding_ok:
            stats["evidence_grounding_pass"] += 1

        # E. Gemini Structured Report Validation
        required_keys = {
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
        report_ok = required_keys.issubset(set(triage_report.keys()))
        if report_ok:
            stats["gemini_report_success"] += 1

        # Human review enforcement
        human_review_ok = triage_report.get("analyst_review_required") is True
        if human_review_ok:
            stats["human_review_enforced"] += 1

        # Overall scenario outcome
        scenario_passed = (
            parser_ok
            and mitre_ok
            and expected_mitre_found
            and pb_ok
            and expected_pb_found
            and cisa_ok
            and ti_ok
            and grounding_ok
            and report_ok
            and human_review_ok
        )

        status_str = "PASS" if scenario_passed else "FAIL"
        per_alert_results.append((s_id, s_name, status_str, {
            "Parser": parser_ok,
            "MITRE Retrieval": mitre_ok,
            "Expected MITRE Match": expected_mitre_found,
            "Playbook Retrieval": pb_ok,
            "Expected Playbook Match": expected_pb_found,
            "CISA Guidance": cisa_ok,
            "Threat Intelligence": ti_ok,
            "Evidence Grounding": grounding_ok,
            "Gemini Report": report_ok,
            "Human Review Enforced": human_review_ok,
        }))

        print(f"Parser                : {'PASS' if parser_ok else 'FAIL'}")
        print(f"MITRE Candidates      : {retrieved_tids[:3]} ({'PASS' if expected_mitre_found else 'FAIL'})")
        print(f"Playbook Retrieved    : {retrieved_pbs[:2]} ({'PASS' if expected_pb_found else 'FAIL'})")
        print(f"CISA Guidance Items   : {len(cisa_ev)} chunks ({'PASS' if cisa_ok else 'FAIL'})")
        print(f"Threat Intelligence   : {len(ti_results)} IOCs ({'PASS' if ti_ok else 'FAIL'})")
        print(f"Evidence Grounding    : {'PASS' if grounding_ok else 'FAIL'}")
        print(f"Gemini Report Keys    : {'PASS' if report_ok else 'FAIL'}")
        print(f"Human Review Flag     : {'PASS' if human_review_ok else 'FAIL'}")
        print(f"Result for [{s_name}]: {status_str}")

    # =========================================================================
    # SUMMARY & METRICS DISPLAY
    # =========================================================================
    print("\n" + "=" * 60)
    print("SUMMARY")
    print("=" * 60)
    print(f"Alerts Tested              : {total_scenarios}")
    print(f"Parser Success             : {stats['parser_success']}/{total_scenarios} ({stats['parser_success']/total_scenarios*100:.1f}%)")
    print(f"MITRE Retrieval            : {stats['mitre_retrieval_success']}/{total_scenarios} ({stats['mitre_retrieval_success']/total_scenarios*100:.1f}%)")
    print(f"Expected MITRE Presence    : {stats['expected_mitre_presence']}/{total_scenarios} ({stats['expected_mitre_presence']/total_scenarios*100:.1f}%)")
    print(f"Playbook Retrieval         : {stats['playbook_retrieval_success']}/{total_scenarios} ({stats['playbook_retrieval_success']/total_scenarios*100:.1f}%)")
    print(f"Expected Playbook Presence : {stats['expected_playbook_presence']}/{total_scenarios} ({stats['expected_playbook_presence']/total_scenarios*100:.1f}%)")
    print(f"CISA Retrieval             : {stats['cisa_retrieval_success']}/{total_scenarios} ({stats['cisa_retrieval_success']/total_scenarios*100:.1f}%)")
    print(f"TI Processing              : {stats['ti_processing_success']}/{total_scenarios} ({stats['ti_processing_success']/total_scenarios*100:.1f}%)")
    print(f"Evidence Grounding         : {stats['evidence_grounding_pass']}/{total_scenarios} ({stats['evidence_grounding_pass']/total_scenarios*100:.1f}%)")
    print(f"Gemini Structured Reports  : {stats['gemini_report_success']}/{total_scenarios} ({stats['gemini_report_success']/total_scenarios*100:.1f}%)")
    print(f"Human Review Enforcement   : {stats['human_review_enforced']}/{total_scenarios} ({stats['human_review_enforced']/total_scenarios*100:.1f}%)")

    all_passed = all(status == "PASS" for _, _, status, _ in per_alert_results)
    overall_status = "PASS" if all_passed else "NEEDS IMPROVEMENT"
    print(f"\nOverall: {overall_status}")
    print("=" * 60 + "\n")

    return all_passed


if __name__ == "__main__":
    success = run_end_to_end_evaluation()
    sys.exit(0 if success else 1)
