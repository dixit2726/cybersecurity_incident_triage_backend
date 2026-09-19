import os
import sys

# Ensure project root is in sys.path
PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from src.rag.mitre_retriever import MitreRetriever


def main():
    retriever = MitreRetriever()

    queries = [
        "PowerShell was used to execute a command.",
        "The attacker created a scheduled task to maintain persistence.",
        "The attacker executed an encoded PowerShell command."
    ]

    print("=" * 60)
    print("MITRE ATT&CK BEHAVIORAL QUERIES EVALUATION")
    print("=" * 60)

    for i, query in enumerate(queries, start=1):
        print(f"\n{'=' * 60}")
        print(f"TEST QUERY [{i}]: {query}")
        print("=" * 60)

        results = retriever.retrieve(query, top_k=5)

        for rank, result in enumerate(results, start=1):
            print(
                f"[{rank}] {result['technique_id']} - {result['technique_name']} "
                f"(Score: {result['score']:.4f})"
            )


if __name__ == "__main__":
    main()
