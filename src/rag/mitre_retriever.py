import json
import os

import faiss
import numpy as np
from sentence_transformers import SentenceTransformer


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


# ---------------------------------------------------------
# Model
# ---------------------------------------------------------

MODEL_NAME = "all-MiniLM-L6-v2"


# ---------------------------------------------------------
# MITRE Retriever
# ---------------------------------------------------------

class MitreRetriever:

    def __init__(self):

        print("Loading MITRE ATT&CK retriever...")

        # Load FAISS index
        print("Loading FAISS index...")
        self.index = faiss.read_index(INDEX_FILE)

        # Load metadata
        print("Loading metadata...")
        with open(
            METADATA_FILE,
            "r",
            encoding="utf-8"
        ) as f:
            self.metadata = json.load(f)

        # Load chunks
        print("Loading chunks...")
        with open(
            CHUNKS_FILE,
            "r",
            encoding="utf-8"
        ) as f:
            self.chunks = json.load(f)

        # Load embedding model
        print("Loading embedding model...")
        self.model = SentenceTransformer(MODEL_NAME)

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
                "FAISS index count does not match metadata count."
            )

        if len(self.metadata) != len(self.chunks):

            raise ValueError(
                "Metadata count does not match chunk count."
            )


    # -----------------------------------------------------
    # Retrieve
    # -----------------------------------------------------

    def retrieve(
        self,
        query: str,
        top_k: int = 5
    ):

        if not query or not query.strip():

            raise ValueError(
                "Query cannot be empty."
            )

        # Generate query embedding
        query_embedding = self.model.encode(
            [query],
            normalize_embeddings=True
        )

        query_embedding = np.asarray(
            query_embedding,
            dtype="float32"
        )

        # Search FAISS
        scores, indices = self.index.search(
            query_embedding,
            top_k
        )

        results = []

        for score, idx in zip(
            scores[0],
            indices[0]
        ):

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
                "text": chunk["text"]
            })

        return results


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