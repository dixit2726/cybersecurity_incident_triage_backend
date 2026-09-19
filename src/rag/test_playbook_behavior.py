import os
import sys

# Ensure project root is in sys.path
PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from src.rag.playbook_retriever import PlaybookRetriever


def main():
    retriever = PlaybookRetriever()

    test_cases = [
        {
            "id": 1,
            "query": "Multiple failed SSH login attempts were detected against a server from the same external IP.",
            "expected_playbook": "Brute Force Attack"
        },
        {
            "id": 2,
            "query": "A suspicious executable was detected on an endpoint and the host may be infected with malware.",
            "expected_playbook": "Malware Infection"
        },
        {
            "id": 3,
            "query": "A user received a suspicious email containing a malicious link and entered credentials into the fake website.",
            "expected_playbook": "Phishing Attack"
        },
        {
            "id": 4,
            "query": "PowerShell executed an encoded command and downloaded a suspicious payload.",
            "expected_playbook": "Suspicious PowerShell Execution"
        },
        {
            "id": 5,
            "query": "A user's account showed an impossible travel login followed by an unexpected MFA registration.",
            "expected_playbook": "Credential Compromise"
        },
        {
            "id": 6,
            "query": "An internal workstation repeatedly connected to a suspicious external IP at regular intervals and transferred an unusually large amount of data.",
            "expected_playbook": "Suspicious IP and Network Activity"
        }
    ]

    print("=" * 60)
    print("PLAYBOOKS RAG BEHAVIORAL RETRIEVAL EVALUATION")
    print("=" * 60)
    print("NOTE: Similarity scores are semantic vector inner-product retrieval")
    print("scores (cosine similarity) and are NOT confidence percentages.")
    print("=" * 60)

    summary_results = []

    for test in test_cases:
        q_id = test["id"]
        query = test["query"]
        expected = test["expected_playbook"]

        print(f"\n{'=' * 60}")
        print(f"QUERY [{q_id}]: {query}")
        print(f"Expected Playbook : {expected}")
        print("=" * 60)

        results = retriever.retrieve(query, top_k=5)

        top_playbook = results[0]["playbook_name"] if results else "None"
        top_score = results[0]["score"] if results else 0.0

        summary_results.append({
            "id": q_id,
            "query": query,
            "expected": expected,
            "top_retrieved": top_playbook,
            "top_score": top_score
        })

        for rank, res in enumerate(results, start=1):
            print(f"\n[{rank}]")
            print(f"Playbook Name : {res['playbook_name']}")
            print(f"Incident Type : {res['incident_type']}")
            print(f"Score         : {res['score']:.4f}")
            print(f"Source        : {res['source']}")
            print(f"Chunk ID      : {res['chunk_id']}")

    print("\n" + "=" * 60)
    print("PLAYBOOK RETRIEVAL SUMMARY")
    print("=" * 60)
    print("NOTE: Similarity scores represent semantic distance, not confidence %.\n")

    for item in summary_results:
        match_flag = "MATCH" if item["expected"].lower() in item["top_retrieved"].lower() or item["top_retrieved"].lower() in item["expected"].lower() else "DIFFERENT"
        print(f"Query [{item['id']}]:")
        print(f"  Expected   : {item['expected']}")
        print(f"  Top Result : {item['top_retrieved']} (Score: {item['top_score']:.4f}) -> [{match_flag}]")
        print()

    print("=" * 60)
    print("EVALUATION COMPLETE")
    print("=" * 60)


if __name__ == "__main__":
    main()
