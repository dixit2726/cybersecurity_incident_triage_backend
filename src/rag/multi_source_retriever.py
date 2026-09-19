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

from typing import Any, Dict, Optional
import numpy as np
from src.rag.cisa_retriever import CisaRetriever
from src.rag.embedding_provider import GeminiEmbeddingProvider, get_embedding_provider
from src.rag.mitre_retriever import MitreRetriever
from src.rag.playbook_retriever import PlaybookRetriever


# ---------------------------------------------------------
# Multi-Source Retriever
# ---------------------------------------------------------

class MultiSourceRetriever:

    def __init__(self, embedding_provider: Optional[GeminiEmbeddingProvider] = None):
        print("Initializing Multi-Source RAG Orchestrator...")
        self.embedding_provider = embedding_provider or get_embedding_provider()

        print("1. Loading MITRE ATT&CK retriever...")
        self.mitre_retriever = MitreRetriever(embedding_provider=self.embedding_provider)

        print("2. Loading Incident Playbooks retriever...")
        self.playbook_retriever = PlaybookRetriever(embedding_provider=self.embedding_provider)

        print("3. Loading CISA Guidance retriever...")
        self.cisa_retriever = CisaRetriever(embedding_provider=self.embedding_provider)

        print("Multi-Source RAG Orchestrator ready.\n")

    def retrieve_by_vector(
        self,
        query_vector: np.ndarray,
        query: str = "",
        mitre_top_k: int = 5,
        playbook_top_k: int = 5,
        cisa_top_k: int = 5
    ) -> Dict[str, Any]:
        """Query all three retrievers independently using a precomputed query vector."""
        mitre_results = self.mitre_retriever.search_by_vector(query_vector, top_k=mitre_top_k)
        playbook_results = self.playbook_retriever.search_by_vector(query_vector, top_k=playbook_top_k)
        cisa_results = self.cisa_retriever.search_by_vector(query_vector, top_k=cisa_top_k)

        # Normalize CISA items to ensure required dictionary keys are cleanly present
        formatted_cisa = []
        for item in cisa_results:
            entry = {
                "score": float(item["score"]),
                "document_title": item.get("document_title"),
                "category": item.get("category"),
                "source_type": item.get("source_type"),
                "source": item.get("source"),
                "chunk_id": item.get("chunk_id"),
                "text": item.get("text"),
            }
            if "page_start" in item:
                entry["page_start"] = item["page_start"]
            if "page_end" in item:
                entry["page_end"] = item["page_end"]
            formatted_cisa.append(entry)

        formatted_mitre = []
        for item in mitre_results:
            formatted_mitre.append({
                "score": float(item["score"]),
                "technique_id": item.get("technique_id"),
                "technique_name": item.get("technique_name"),
                "source": item.get("source"),
                "chunk_id": item.get("chunk_id"),
                "text": item.get("text"),
            })

        formatted_playbooks = []
        for item in playbook_results:
            formatted_playbooks.append({
                "score": float(item["score"]),
                "playbook_name": item.get("playbook_name"),
                "incident_type": item.get("incident_type"),
                "source": item.get("source"),
                "chunk_id": item.get("chunk_id"),
                "text": item.get("text"),
            })

        return {
            "query": query,
            "mitre": formatted_mitre,
            "playbooks": formatted_playbooks,
            "cisa": formatted_cisa,
            "summary": {
                "mitre_results": len(formatted_mitre),
                "playbook_results": len(formatted_playbooks),
                "cisa_results": len(formatted_cisa),
            }
        }

    def retrieve(
        self,
        query: str,
        mitre_top_k: int = 5,
        playbook_top_k: int = 5,
        cisa_top_k: int = 5
    ) -> Dict[str, Any]:
        """
        Embed the incident query ONCE using the shared Gemini embedding provider,
        then query MITRE, Playbooks, and CISA retrievers with the vector.
        Scores remain strictly source-specific without cross-source merging or comparison.
        """
        if not query or not query.strip():
            raise ValueError("Query cannot be empty.")

        try:
            query_vector = self.embedding_provider.embed_text(query)
            return self.retrieve_by_vector(
                query_vector,
                query=query,
                mitre_top_k=mitre_top_k,
                playbook_top_k=playbook_top_k,
                cisa_top_k=cisa_top_k,
            )
        except Exception as e:
            print(f"[WARNING] MultiSourceRetriever embedding failed ({e}). Returning graceful fallback empty candidate lists.")
            return {
                "query": query,
                "mitre": [],
                "playbooks": [],
                "cisa": [],
                "summary": {
                    "mitre_results": 0,
                    "playbook_results": 0,
                    "cisa_results": 0,
                },
            }


# ---------------------------------------------------------
# Command-Line Test
# ---------------------------------------------------------

def main():
    retriever = MultiSourceRetriever()

    incident_query = (
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
    print("MULTI-SOURCE RAG TEST")
    print("=" * 60)

    print(f"\nQUERY:\n{incident_query}\n")

    response = retriever.retrieve(
        incident_query,
        mitre_top_k=5,
        playbook_top_k=5,
        cisa_top_k=5
    )

    # ---------------------------------------------------------
    # MITRE Evidence
    # ---------------------------------------------------------
    print("=" * 60)
    print("MITRE EVIDENCE")
    print("=" * 60)

    for rank, item in enumerate(response["mitre"], start=1):
        print(f"\n[{rank}]")
        print(f"Technique: {item['technique_id']} - {item['technique_name']}")
        print(f"Score: {item['score']:.4f}")
        print(f"Source: {item['source']}")
        print(f"Chunk ID: {item['chunk_id']}")
        print(f"Text:\n{item['text']}")
        print("-" * 60)

    # ---------------------------------------------------------
    # Playbook Evidence
    # ---------------------------------------------------------
    print("\n" + "=" * 60)
    print("PLAYBOOK EVIDENCE")
    print("=" * 60)

    for rank, item in enumerate(response["playbooks"], start=1):
        print(f"\n[{rank}]")
        print(f"Playbook: {item['playbook_name']}")
        print(f"Incident Type: {item['incident_type']}")
        print(f"Score: {item['score']:.4f}")
        print(f"Source: {item['source']}")
        print(f"Chunk ID: {item['chunk_id']}")
        print(f"Text:\n{item['text']}")
        print("-" * 60)

    # ---------------------------------------------------------
    # CISA Evidence
    # ---------------------------------------------------------
    print("\n" + "=" * 60)
    print("CISA EVIDENCE")
    print("=" * 60)

    for rank, item in enumerate(response["cisa"], start=1):
        print(f"\n[{rank}]")
        print(f"Document: {item['document_title']}")
        print(f"Category: {item['category']}")
        print(f"Score: {item['score']:.4f}")
        print(f"Source: {item['source']}")
        print(f"Chunk ID: {item['chunk_id']}")
        if "page_start" in item and item["page_start"] is not None:
            p_start = item["page_start"]
            p_end = item.get("page_end", p_start)
            print(f"Pages: {p_start} - {p_end}")
        print(f"Text:\n{item['text']}")
        print("-" * 60)

    # ---------------------------------------------------------
    # Multi-Source RAG Summary
    # ---------------------------------------------------------
    print("\n" + "=" * 60)
    print("MULTI-SOURCE RAG SUMMARY")
    print("=" * 60)

    summary = response["summary"]
    print(f"MITRE results: {summary['mitre_results']}")
    print(f"Playbook results: {summary['playbook_results']}")
    print(f"CISA results: {summary['cisa_results']}")

    print("\n" + "=" * 60)
    print("NOTE:")
    print("Similarity scores are source-specific retrieval similarity scores.")
    print("They are NOT confidence percentages and must NOT be compared directly across MITRE, Playbooks, and CISA.")
    print("=" * 60 + "\n")


if __name__ == "__main__":
    main()
