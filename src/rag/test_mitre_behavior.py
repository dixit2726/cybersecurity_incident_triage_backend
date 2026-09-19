import os
import sys

# Ensure project root is in sys.path
PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from src.rag.mitre_retriever import MitreRetriever


def main():
    retriever = MitreRetriever()

    behavioral_incident = """
A suspicious PowerShell process executed an encoded command.
The process then created a scheduled task to maintain persistence
after system startup.
"""

    results = retriever.retrieve(
        behavioral_incident,
        top_k=5
    )

    print("=" * 60)
    print("MITRE ATT&CK BEHAVIORAL TEST")
    print("=" * 60)
    print("\nBehavioral Incident:")
    print(behavioral_incident.strip())

    print("\n" + "=" * 60)
    print("MITRE ATT&CK RESULTS")
    print("=" * 60)

    for rank, result in enumerate(results, start=1):
        print(f"\n[{rank}]")
        print(f"Technique : {result['technique_id']} - {result['technique_name']}")
        print(f"Score     : {result['score']:.4f}")
        print(f"Source    : {result['source']}")
        print(f"Evidence  : {result['text']}")


if __name__ == "__main__":
    main()
