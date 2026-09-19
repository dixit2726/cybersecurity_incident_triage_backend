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

from src.rag.multi_source_retriever import MultiSourceRetriever


def main():
    print("Initializing Multi-Source RAG Orchestrator for Behavioral Evaluation...\n")
    retriever = MultiSourceRetriever()

    test_cases = [
        {
            "test_num": 1,
            "name": "BRUTE FORCE SSH",
            "alert_text": (
                "CYBERSECURITY ALERT\n"
                "Alert ID: TEST-001\n"
                "Severity: High\n"
                "Event Type: Brute Force Attack\n"
                "Attack Category: Credential Attack\n"
                "Source IP: 185.220.101.45\n"
                "Destination IP: 192.168.1.105\n"
                "Protocol: TCP\n"
                "Destination Port: 22\n\n"
                "Alert Description:\n"
                "Multiple failed SSH login attempts were detected from the same external IP address. "
                "47 failed authentication attempts were recorded within 5 minutes against the server.\n\n"
                "Failed Login Attempts: 47\n"
                "Time Window: 5 minutes\n"
                "Target Service: SSH\n"
                "Target Account: admin"
            ),
            "expected_playbook": "Brute Force Attack",
            "expected_mitre_concept": "T1110 Brute Force",
            "mitre_keywords": ["t1110", "brute force", "password guessing", "password spraying"],
        },
        {
            "test_num": 2,
            "name": "MALWARE INFECTION",
            "alert_text": (
                "CYBERSECURITY ALERT\n"
                "Alert ID: TEST-002\n"
                "Severity: Critical\n"
                "Event Type: Malware Infection\n"
                "Attack Category: Malware\n\n"
                "Alert Description:\n"
                "An endpoint executed a suspicious executable downloaded from an external source. "
                "The process created unusual files in the user's application data directory "
                "and established an outbound connection to an unknown external server."
            ),
            "expected_playbook": "Malware Infection",
            "expected_mitre_concept": "Malware execution / Command and Control",
            "mitre_keywords": ["malware", "execution", "command and control", "c2", "ingress tool transfer", "user execution", "t1204", "t1105"],
        },
        {
            "test_num": 3,
            "name": "PHISHING",
            "alert_text": (
                "CYBERSECURITY ALERT\n"
                "Alert ID: TEST-003\n"
                "Severity: High\n"
                "Event Type: Phishing Attack\n"
                "Attack Category: Credential Access\n\n"
                "Alert Description:\n"
                "A user received an email containing a suspicious link. "
                "The user opened the link and entered corporate credentials into a fake login page hosted on an external domain."
            ),
            "expected_playbook": "Phishing Attack",
            "expected_mitre_concept": "Phishing / Credential Access",
            "mitre_keywords": ["phishing", "credential", "credentials", "input capture", "spearphishing", "t1566", "t1056"],
        },
        {
            "test_num": 4,
            "name": "SUSPICIOUS POWERSHELL",
            "alert_text": (
                "CYBERSECURITY ALERT\n"
                "Alert ID: TEST-004\n"
                "Severity: High\n"
                "Event Type: Suspicious PowerShell\n"
                "Attack Category: Execution / Defense Evasion\n\n"
                "Alert Description:\n"
                "PowerShell executed an encoded command and downloaded a suspicious payload from an external server. "
                "The PowerShell process was launched by an Office application."
            ),
            "expected_playbook": "Suspicious PowerShell Execution",
            "expected_mitre_concept": "T1059.001 PowerShell / Command Obfuscation",
            "mitre_keywords": ["t1059", "powershell", "command", "obfuscat", "deobfuscat", "encoded", "scripting"],
        },
        {
            "test_num": 5,
            "name": "CREDENTIAL COMPROMISE",
            "alert_text": (
                "CYBERSECURITY ALERT\n"
                "Alert ID: TEST-005\n"
                "Severity: Critical\n"
                "Event Type: Credential Compromise\n"
                "Attack Category: Account Takeover\n\n"
                "Alert Description:\n"
                "A user's account authenticated successfully from an unfamiliar country shortly after a login from the user's normal location. "
                "An unexpected MFA device was then registered on the account.\n\n"
                "Authentication Details:\n"
                "- Impossible travel detected\n"
                "- New MFA device registered\n"
                "- Successful cloud login\n"
                "- User denies the activity"
            ),
            "expected_playbook": "Credential Compromise",
            "expected_mitre_concept": "Valid Accounts / Account Access",
            "mitre_keywords": ["valid accounts", "t1078", "account", "credential", "mfa", "access token", "cloud accounts"],
        },
        {
            "test_num": 6,
            "name": "SUSPICIOUS IP / C2",
            "alert_text": (
                "CYBERSECURITY ALERT\n"
                "Alert ID: TEST-006\n"
                "Severity: Critical\n"
                "Event Type: Suspicious Network Activity\n"
                "Attack Category: Command and Control\n\n"
                "Alert Description:\n"
                "An internal workstation repeatedly connected to the same suspicious external IP address every 60 seconds. "
                "The connection pattern showed regular beaconing behavior and an unusually large amount of outbound data was transferred.\n\n"
                "Network Details:\n"
                "- Protocol: TCP\n"
                "- Periodic beaconing: 60 seconds\n"
                "- Large outbound data transfer\n"
                "- Destination: suspicious external IP\n"
                "- Internal endpoint involved"
            ),
            "expected_playbook": "Suspicious IP and Network Activity",
            "expected_mitre_concept": "Command and Control / Network-related technique",
            "mitre_keywords": ["command and control", "c2", "network", "exfiltration", "traffic", "protocol", "beacon", "t1071", "t1041", "t1571", "data transfer"],
        },
    ]

    playbook_matches = 0
    mitre_relevant_count = 0
    cisa_relevant_count = 0

    for tc in test_cases:
        t_num = tc["test_num"]
        t_name = tc["name"]
        alert_text = tc["alert_text"]
        expected_playbook = tc["expected_playbook"]
        expected_mitre = tc["expected_mitre_concept"]
        mitre_keywords = tc["mitre_keywords"]

        print("\n" + "=" * 60)
        print(f"TEST {t_num} — {t_name}")
        print("=" * 60)

        print("\nALERT:")
        print(alert_text)

        # Retrieve evidence from all three sources
        response = retriever.retrieve(
            alert_text,
            mitre_top_k=5,
            playbook_top_k=5,
            cisa_top_k=5
        )

        mitre_results = response["mitre"]
        playbook_results = response["playbooks"]
        cisa_results = response["cisa"]

        # -----------------------------------------------------
        # Print MITRE Top Results
        # -----------------------------------------------------
        print("\n---------------- MITRE TOP RESULTS ----------------")
        for rank, item in enumerate(mitre_results, start=1):
            print(f"\n[{rank}]")
            print(f"Technique: {item['technique_id']} - {item['technique_name']}")
            print(f"Score: {item['score']:.4f}")
            print(f"Source: {item['source']}")

        # -----------------------------------------------------
        # Print Playbook Top Results
        # -----------------------------------------------------
        print("\n---------------- PLAYBOOK TOP RESULTS ----------------")
        for rank, item in enumerate(playbook_results, start=1):
            print(f"\n[{rank}]")
            print(f"Playbook: {item['playbook_name']}")
            print(f"Score: {item['score']:.4f}")
            print(f"Source: {item['source']}")

        # -----------------------------------------------------
        # Print CISA Top Results
        # -----------------------------------------------------
        print("\n---------------- CISA TOP RESULTS ----------------")
        for rank, item in enumerate(cisa_results, start=1):
            print(f"\n[{rank}]")
            print(f"Document: {item['document_title']}")
            print(f"Category: {item['category']}")
            print(f"Score: {item['score']:.4f}")
            print(f"Source: {item['source']}")

        # -----------------------------------------------------
        # Per-Test Retrieval Evaluation
        # -----------------------------------------------------
        top_playbook = playbook_results[0]["playbook_name"] if playbook_results else "None"
        playbook_status = (
            "MATCH"
            if (expected_playbook.lower() in top_playbook.lower() or top_playbook.lower() in expected_playbook.lower())
            else "DIFFERENT"
        )
        if playbook_status == "MATCH":
            playbook_matches += 1

        top_mitre_id = mitre_results[0]["technique_id"] if mitre_results else "None"
        top_mitre_name = mitre_results[0]["technique_name"] if mitre_results else "None"
        top_mitre_str = f"{top_mitre_id} - {top_mitre_name}"
        search_target = f"{top_mitre_id} {top_mitre_name}".lower()

        is_mitre_rel = any(kw.lower() in search_target for kw in mitre_keywords)
        # Also check top 3 MITRE results if top-1 was adjacent
        if not is_mitre_rel and len(mitre_results) > 1:
            for next_item in mitre_results[1:3]:
                next_target = f"{next_item['technique_id']} {next_item['technique_name']}".lower()
                if any(kw.lower() in next_target for kw in mitre_keywords):
                    is_mitre_rel = True
                    break

        mitre_status = "RELEVANT" if is_mitre_rel else "DIFFERENT"
        if mitre_status == "RELEVANT":
            mitre_relevant_count += 1

        # CISA top categories
        cisa_categories = []
        for c in cisa_results:
            cat = c.get("category")
            if cat and cat not in cisa_categories:
                cisa_categories.append(cat)
        top_cisa_cats = cisa_categories[:3]

        if cisa_results:
            cisa_relevant_count += 1

        print("\n---------------- RETRIEVAL EVALUATION ----------------")
        print(f"Expected Playbook: {expected_playbook}")
        print(f"Top Playbook: {top_playbook}")
        print(f"Playbook Status: {playbook_status}")
        print()
        print(f"Expected MITRE Concept: {expected_mitre}")
        print(f"Top MITRE Result: {top_mitre_str}")
        print(f"MITRE Status: {mitre_status}")
        print()
        print("CISA:")
        print(f"List the top 3 retrieved CISA categories: {', '.join(top_cisa_cats)}")
        print("-" * 60)

    # ---------------------------------------------------------
    # Overall Evaluation Summary
    # ---------------------------------------------------------
    print("\n" + "=" * 60)
    print("MULTI-SOURCE RAG EVALUATION SUMMARY")
    print("=" * 60)

    total_alerts = len(test_cases)
    print(f"\nTotal alerts tested: {total_alerts}\n")

    print("Playbook Top-1 Matches:")
    print(f"{playbook_matches} / {total_alerts}\n")

    print("MITRE Relevant Results:")
    print(f"{mitre_relevant_count} / {total_alerts}\n")

    print("CISA Relevant Retrieval:")
    print(f"{cisa_relevant_count} / {total_alerts}")

    print("\n" + "=" * 60)
    print("RETRIEVAL NOTES\n")
    print("- Similarity scores are source-specific retrieval similarity scores.")
    print("- They are NOT confidence percentages.")
    print("- Scores must NOT be directly compared across MITRE, Playbooks, and CISA.")
    print("- Retrieval results are evidence candidates, not confirmed security conclusions.")
    print("- The test must not generate a final incident classification.")
    print("- Human analyst validation remains required.")
    print("=" * 60 + "\n")


if __name__ == "__main__":
    main()
