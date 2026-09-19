import json
import os
import sys
from typing import Any, Dict, List, Optional

import faiss
import numpy as np
from src.rag.embedding_provider import GeminiEmbeddingProvider, get_embedding_provider

# Ensure project root is in sys.path
PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)


# ---------------------------------------------------------
# Paths
# ---------------------------------------------------------

INDEX_FILE = os.path.join(
    "data",
    "rag",
    "playbooks",
    "vector_store",
    "playbooks.index"
)

METADATA_FILE = os.path.join(
    "data",
    "rag",
    "playbooks",
    "embeddings",
    "playbook_embedding_metadata.json"
)

CHUNKS_FILE = os.path.join(
    "data",
    "rag",
    "playbooks",
    "chunks",
    "playbook_chunks.json"
)


def resolve_path(path: str) -> str:
    """
    Resolve path relative to current working directory or project root.
    """
    if os.path.isabs(path) and os.path.exists(path):
        return path

    if os.path.exists(path):
        return os.path.abspath(path)

    script_relative = os.path.abspath(
        os.path.join(
            os.path.dirname(__file__),
            "..",
            "..",
            path
        )
    )
    if os.path.exists(script_relative):
        return script_relative

    return os.path.abspath(path)


# ---------------------------------------------------------
# Playbook Retriever
# ---------------------------------------------------------

class PlaybookRetriever:

    def __init__(
        self,
        index_file: str = INDEX_FILE,
        metadata_file: str = METADATA_FILE,
        chunks_file: str = CHUNKS_FILE,
        embedding_provider: Optional[GeminiEmbeddingProvider] = None,
    ):
        print("Loading Playbooks retriever...")

        resolved_index_file = resolve_path(index_file)
        resolved_metadata_file = resolve_path(metadata_file)
        resolved_chunks_file = resolve_path(chunks_file)

        # Load FAISS index
        print(f"Loading FAISS index from: {resolved_index_file}")
        if not os.path.exists(resolved_index_file):
            raise FileNotFoundError(f"FAISS index file not found: {resolved_index_file}")
        self.index = faiss.read_index(resolved_index_file)

        # Load metadata
        print(f"Loading metadata from: {resolved_metadata_file}")
        if not os.path.exists(resolved_metadata_file):
            raise FileNotFoundError(f"Metadata file not found: {resolved_metadata_file}")
        with open(resolved_metadata_file, "r", encoding="utf-8") as f:
            self.metadata = json.load(f)

        # Load chunks
        print(f"Loading chunks from: {resolved_chunks_file}")
        if not os.path.exists(resolved_chunks_file):
            raise FileNotFoundError(f"Chunks file not found: {resolved_chunks_file}")
        with open(resolved_chunks_file, "r", encoding="utf-8") as f:
            self.chunks = json.load(f)

        # Shared embedding provider
        self.embedding_provider = embedding_provider or get_embedding_provider()

        # Validate alignment
        self._validate()

        print(
            f"Playbooks retriever ready "
            f"({self.index.ntotal:,} vectors indexed)"
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
                "playbook_name": metadata["playbook_name"],
                "incident_type": metadata["incident_type"],
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
    retriever = PlaybookRetriever()

    query = "The attacker performed multiple failed SSH login attempts against a server."

    print("\n" + "=" * 60)
    print("PLAYBOOK RETRIEVAL TEST")
    print("=" * 60)

    print(f"\nQuery:\n{query}")

    results = retriever.retrieve(
        query,
        top_k=5
    )

    for rank, result in enumerate(results, start=1):
        print(f"\n[{rank}]")
        print(f"Playbook     : {result['playbook_name']}")
        print(f"Incident Type: {result['incident_type']}")
        print(f"Score        : {result['score']:.4f}")
        print(f"Source       : {result['source']}")
        print(f"Chunk ID     : {result['chunk_id']}")
        print("\nText:")
        print(result["text"])

    print("\n" + "=" * 60)
    print("PLAYBOOK RETRIEVAL TEST COMPLETE")
    print("=" * 60)
