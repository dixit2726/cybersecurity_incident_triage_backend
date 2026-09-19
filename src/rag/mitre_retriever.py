import json
import os
import sys
from typing import Any, Dict, List, Optional

import faiss
import numpy as np
from src.rag.embedding_provider import GeminiEmbeddingProvider, get_embedding_provider

PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)


# ---------------------------------------------------------
# Paths
# ---------------------------------------------------------

INDEX_FILE = os.path.join(
    "data",
    "rag",
    "mitre",
    "vector_store",
    "mitre.index"
)

METADATA_FILE = os.path.join(
    "data",
    "rag",
    "mitre",
    "embeddings",
    "mitre_embedding_metadata.json"
)

CHUNKS_FILE = os.path.join(
    "data",
    "rag",
    "mitre",
    "chunks",
    "mitre_chunks.json"
)


def resolve_path(path: str) -> str:
    """Resolve path relative to current working directory or project root."""
    if os.path.isabs(path) and os.path.exists(path):
        return path
    if os.path.exists(path):
        return os.path.abspath(path)
    project_root = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
    proj_path = os.path.join(project_root, path)
    if os.path.exists(proj_path):
        return proj_path
    return os.path.abspath(path)


# ---------------------------------------------------------
# MITRE Retriever
# ---------------------------------------------------------

class MitreRetriever:

    def __init__(
        self,
        index_file: str = INDEX_FILE,
        metadata_file: str = METADATA_FILE,
        chunks_file: str = CHUNKS_FILE,
        embedding_provider: Optional[GeminiEmbeddingProvider] = None,
    ):
        print("Loading MITRE ATT&CK retriever...")

        resolved_index_file = resolve_path(index_file)
        resolved_metadata_file = resolve_path(metadata_file)
        resolved_chunks_file = resolve_path(chunks_file)

        # Load FAISS index
        print("Loading FAISS index...")
        self.index = faiss.read_index(resolved_index_file)

        # Load metadata
        print("Loading metadata...")
        with open(resolved_metadata_file, "r", encoding="utf-8") as f:
            self.metadata = json.load(f)

        # Load chunks
        print("Loading chunks...")
        with open(resolved_chunks_file, "r", encoding="utf-8") as f:
            self.chunks = json.load(f)

        if len(self.chunks) > len(self.metadata):
            self.chunks = self.chunks[:len(self.metadata)]

        # Shared embedding provider
        self.embedding_provider = embedding_provider or get_embedding_provider()

        # Validate
        self._validate()

        print(
            f"MITRE retriever ready "
            f"({self.index.ntotal:,} vectors)"
        )

    # -----------------------------------------------------
    # Validation
    # -----------------------------------------------------

    def _validate(self):
        if self.index.ntotal != len(self.metadata):
            raise ValueError(
                f"FAISS index count ({self.index.ntotal}) does not match metadata count ({len(self.metadata)})."
            )

        if len(self.metadata) != len(self.chunks):
            raise ValueError(
                f"Metadata count ({len(self.metadata)}) does not match chunk count ({len(self.chunks)})."
            )

    # -----------------------------------------------------
    # Retrieve
    # -----------------------------------------------------

    def search_by_vector(
        self,
        query_embedding: np.ndarray,
        top_k: int = 5,
    ) -> List[Dict[str, Any]]:
        """Search FAISS index directly using a precomputed query vector."""
        if query_embedding.ndim == 1:
            query_embedding = np.asarray([query_embedding], dtype=np.float32)
        elif query_embedding.dtype != np.float32:
            query_embedding = query_embedding.astype(np.float32)

        scores, indices = self.index.search(query_embedding, top_k)
        results = []

        for score, idx in zip(scores[0], indices[0]):
            if idx < 0:
                continue

            chunk = self.chunks[idx]
            metadata = self.metadata[idx]

            results.append({
                "score": float(score),
                "technique_id": metadata["technique_id"],
                "technique_name": metadata["technique_name"],
                "source": metadata["source"],
                "chunk_id": metadata["chunk_id"],
                "text": chunk["text"],
            })

        return results

    def retrieve(
        self,
        query: str,
        top_k: int = 5,
    ) -> List[Dict[str, Any]]:
        if not query or not query.strip():
            raise ValueError("Query cannot be empty.")

        query_embedding = self.embedding_provider.embed_text(query)
        return self.search_by_vector(query_embedding, top_k=top_k)


# ---------------------------------------------------------
# Test
# ---------------------------------------------------------

if __name__ == "__main__":

    retriever = MitreRetriever()

    query = (
        "How can an attacker use scheduled tasks "
        "for persistence?"
    )

    print("\n" + "=" * 60)
    print("MITRE RETRIEVAL TEST")
    print("=" * 60)

    print(f"\nQuery:\n{query}")

    results = retriever.retrieve(
        query,
        top_k=5
    )

    print("\nTop Results")
    print("-" * 60)

    for rank, result in enumerate(
        results,
        start=1
    ):

        print(f"\n[{rank}]")

        print(
            f"Technique : "
            f"{result['technique_id']} - "
            f"{result['technique_name']}"
        )

        print(
            f"Score     : "
            f"{result['score']:.4f}"
        )

        print(
            f"Source    : "
            f"{result['source']}"
        )

        print(
            f"Chunk ID  : "
            f"{result['chunk_id']}"
        )

        preview = (
            result["text"]
            .replace("\n", " ")
        )

        if len(preview) > 500:
            preview = preview[:500] + "..."

        print(f"Text      : {preview}")

    print("\n" + "=" * 60)
    print("MITRE RETRIEVAL TEST COMPLETE")
    print("=" * 60)