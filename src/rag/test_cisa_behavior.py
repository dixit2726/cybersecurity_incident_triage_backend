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

from src.rag.cisa_retriever import CisaRetriever


def main():
    retriever = CisaRetriever()

    test_queries = [
        {
            "id": 1,
            "query": "How should a security team respond to a ransomware incident and isolate affected systems?",
            "expected_category": "ransomware",
        },
        {
            "id": 2,
            "query": "What should an organization do when investigating a cybersecurity incident and preserving evidence?",
            "expected_category": "incident_response",
        },
        {
            "id": 3,
            "query": "How can organizations improve logging and monitoring to detect suspicious activity?",
            "expected_category": "logging",
        },
        {
            "id": 4,
            "query": "What security measures can improve visibility and hardening of communications infrastructure?",
            "expected_category": "network_visibility",
        },
        {
            "id": 5,
            "query": "What defensive actions are recommended when attackers maintain persistent access to critical infrastructure?",
            "expected_category": "advisories",
        },
        {
            "id": 6,
            "query": "What should defenders do when a threat actor exploits a vulnerable internet-facing system?",
            "expected_category": "advisories",
        },
    ]

    print("\n" + "=" * 60)
    print("CISA RAG BEHAVIORAL RETRIEVAL EVALUATION")
    print("=" * 60)

    summary_items = []

    for test in test_queries:
        q_id = test["id"]
        query = test["query"]
        expected_cat = test["expected_category"]

        print(f"\n{'=' * 60}")
        print(f"QUERY [{q_id}]:")
        print(f"{query}")
        print(f"Expected Category : {expected_cat}")
        print("-" * 60)

        results = retriever.retrieve(query, top_k=5)

        top_cat = results[0]["category"] if results else "None"
        top_score = results[0]["score"] if results else 0.0

        for rank, res in enumerate(results, start=1):
            print(f"\n[{rank}]")
            print(f"Document Title : {res['document_title']}")
            print(f"Category       : {res['category']}")
            print(f"Score          : {res['score']:.4f}")
            print(f"Source         : {res['source']}")
            print(f"Chunk ID       : {res['chunk_id']}")
            if "page_start" in res and res.get("page_start") is not None:
                p_start = res["page_start"]
                p_end = res.get("page_end", p_start)
                print(f"Pages          : {p_start} - {p_end}")

        print(f"\n>>> Top-ranked Category: {top_cat} (Score: {top_score:.4f})")

        is_match = (top_cat.lower() == expected_cat.lower())
        summary_items.append({
            "id": q_id,
            "query": query,
            "expected": expected_cat,
            "top_category": top_cat,
            "top_score": top_score,
            "status": "MATCH" if is_match else "DIFFERENT",
        })

    # Summary Section
    print("\n" + "=" * 60)
    print("CISA BEHAVIORAL RETRIEVAL SUMMARY")
    print("=" * 60)

    for item in summary_items:
        print(f"\nQuery [{item['id']}]:")
        print(f"Expected Category: {item['expected']}")
        print(f"Top Category     : {item['top_category']}")
        print(f"Top Score        : {item['top_score']:.4f}")
        print(f"Status           : {item['status']}")

    print("\n" + "=" * 60)
    print("NOTE:")
    print("Similarity scores represent retrieval similarity, not confidence percentages.")
    print("=" * 60 + "\n")


if __name__ == "__main__":
    main()
