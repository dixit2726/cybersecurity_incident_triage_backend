import json
import os
import sys
from typing import Any, Dict, List

import faiss
import numpy as np
from sentence_transformers import SentenceTransformer

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


# ---------------------------------------------------------
# Paths
# ---------------------------------------------------------

INDEX_FILE = os.path.join(
    "data", "rag", "cisa", "vector_store",
    "cisa.index"
)

METADATA_FILE = os.path.join(
    "data", "rag", "cisa", "embeddings",
    "cisa_embedding_metadata.json"
)

CHUNKS_FILE = os.path.join(
    "data", "rag", "cisa", "chunks",
    "cisa_chunks.json"
)


# ---------------------------------------------------------
# Model
# ---------------------------------------------------------

MODEL_NAME = "all-MiniLM-L6-v2"


def resolve_path(path: str) -> str:
    """
    Resolve path relative to current working directory or project root.
    """
    if os.path.isabs(path) and os.path.exists(path):
        return path

    if os.path.exists(path):
        return os.path.abspath(path)

    project_relative = os.path.abspath(os.path.join(PROJECT_ROOT, path))
    if os.path.exists(project_relative):
        return project_relative

    return os.path.abspath(path)


# ---------------------------------------------------------
# CISA Retriever
# ---------------------------------------------------------

class CisaRetriever:

    def __init__(
        self,
        index_file: str = INDEX_FILE,
        metadata_file: str = METADATA_FILE,
        chunks_file: str = CHUNKS_FILE,
        model_name: str = MODEL_NAME,
    ):
        print("Loading CISA retriever...")

        resolved_index_file = resolve_path(index_file)
        resolved_metadata_file = resolve_path(metadata_file)
        resolved_chunks_file = resolve_path(chunks_file)

        # 1. Load FAISS index
        print(f"Loading FAISS index from: {resolved_index_file}")
        if not os.path.exists(resolved_index_file):
            raise FileNotFoundError(f"FAISS index file not found: {resolved_index_file}")
        self.index = faiss.read_index(resolved_index_file)

        # 2. Load metadata
        print(f"Loading metadata from: {resolved_metadata_file}")
        if not os.path.exists(resolved_metadata_file):
            raise FileNotFoundError(f"Metadata file not found: {resolved_metadata_file}")
        with open(resolved_metadata_file, "r", encoding="utf-8") as f:
            self.metadata = json.load(f)

        # 3. Load chunks
        print(f"Loading chunks from: {resolved_chunks_file}")
        if not os.path.exists(resolved_chunks_file):
            raise FileNotFoundError(f"Chunks file not found: {resolved_chunks_file}")
        with open(resolved_chunks_file, "r", encoding="utf-8") as f:
            self.chunks = json.load(f)

        # 4. Load embedding model
        print(f"Loading embedding model: {model_name}...")
        self.model = SentenceTransformer(model_name)

        # 5. Validate alignment
        self._validate()

        print(
            f"CISA retriever ready "
            f"({self.index.ntotal:,} vectors indexed)"
        )

    def _validate(self):
        """
        Validate alignment between FAISS index, metadata, and original chunks.
        """
        if self.index.ntotal != len(self.metadata):
            raise ValueError(
                f"Validation Failure: FAISS index count ({self.index.ntotal}) "
                f"does not match metadata count ({len(self.metadata)})."
            )

        if len(self.metadata) != len(self.chunks):
            raise ValueError(
                f"Validation Failure: Metadata count ({len(self.metadata)}) "
                f"does not match chunk count ({len(self.chunks)})."
            )

    def retrieve(self, query: str, top_k: int = 5) -> List[Dict[str, Any]]:
        """
        Retrieve top_k most relevant CISA knowledge chunks for a given query.
        """
        if not query or not query.strip():
            raise ValueError("Query cannot be empty.")

        # Generate normalized query embedding
        query_embedding = self.model.encode(
            [query],
            normalize_embeddings=True
        )

        query_embedding = np.asarray(
            query_embedding,
            dtype=np.float32
        )

        # Search FAISS index
        scores, indices = self.index.search(
            query_embedding,
            top_k
        )

        results = []

        for score, idx in zip(scores[0], indices[0]):
            # Ignore invalid FAISS indexes (-1)
            if idx < 0:
                continue

            chunk = self.chunks[idx]
            metadata = self.metadata[idx]

            result_item = {
                "score": float(score),
                "document_title": metadata.get("document_title"),
                "category": metadata.get("category"),
                "source_type": metadata.get("source_type"),
                "source": metadata.get("source"),
                "chunk_id": metadata.get("chunk_id"),
                "text": chunk.get("text"),
            }

            # If page info is present, include it
            if "page_start" in metadata:
                result_item["page_start"] = metadata["page_start"]
            if "page_end" in metadata:
                result_item["page_end"] = metadata["page_end"]

            results.append(result_item)

        return results


# ---------------------------------------------------------
# Command-Line Test
# ---------------------------------------------------------

def main():
    retriever = CisaRetriever()

    test_query = (
        "How should a security team respond to a ransomware incident and contain the affected systems?"
    )

    print("\n" + "=" * 60)
    print("CISA RETRIEVAL TEST")
    print("=" * 60)

    print(f"\nQuery:\n{test_query}\n")

    results = retriever.retrieve(test_query, top_k=5)

    for rank, result in enumerate(results, start=1):
        print(f"[{rank}]")
        print(f"Document Title: {result['document_title']}")
        print(f"Category: {result['category']}")
        print(f"Score: {result['score']:.4f}")
        print(f"Source: {result['source']}")
        print(f"Chunk ID: {result['chunk_id']}")
        if "page_start" in result:
            print(f"Pages: {result['page_start']} - {result['page_end']}")
        print("\nText:")
        print(result["text"])
        print("-" * 60)

    print(
        "\nNote: Similarity scores represent retrieval similarity, not confidence percentages."
    )
    print("=" * 60)
    print("CISA RETRIEVAL TEST COMPLETE")
    print("=" * 60 + "\n")


if __name__ == "__main__":
    main()
