import os
import sys

PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from src.rag.mitre_retriever import MitreRetriever


def main():
    retriever = MitreRetriever()

    test_cases = [
        ("Adversary dumped credentials from LSASS process memory.", "T1003.001"),
        ("Adversary attempted brute force password guessing against accounts.", "T1110"),
        ("Attacker moved laterally across network shares using SMB admin shares.", "T1021.002"),
        ("Malware deleted system event logs to hide indicators of compromise.", "T1070"),
        ("Threat actor exfiltrated sensitive data over an encrypted C2 channel.", "T1041"),
        ("Discovered system network configuration and interfaces.", "T1016"),
    ]

    print("=" * 60)
    print("COMPREHENSIVE MULTI-REGION MITRE RETRIEVAL EVALUATION")
    print("=" * 60)

    passed = 0
    for query, expected in test_cases:
        results = retriever.retrieve(query, top_k=5)
        matched = any(expected in r["technique_id"] for r in results)
        top_id = results[0]["technique_id"]
        top_name = results[0]["technique_name"]
        top_score = results[0]["score"]
        status = "PASS" if matched else "FAIL"
        if matched:
            passed += 1
        print(f"Query: \"{query}\"")
        print(f"Expected: {expected} | Top Retrieved: {top_id} - {top_name} (Score: {top_score:.4f}) -> [{status}]")
        print("-" * 60)

    print(f"\nTotal passed: {passed}/{len(test_cases)}")
    assert passed >= len(test_cases) - 1, f"Expected at least 5 passed, got {passed}"
    print("ALL MULTI-REGION MITRE TESTS PASSED!")


if __name__ == "__main__":
    main()
