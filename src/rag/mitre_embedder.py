import json
import os
import sys
import numpy as np

# Ensure project root is in sys.path
PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from src.rag.embedding_provider import get_embedding_provider


# ---------------------------------------------------------
# Paths
# ---------------------------------------------------------

INPUT_FILE = os.path.join(
    "data",
    "rag",
    "mitre",
    "chunks",
    "mitre_chunks.json"
)

OUTPUT_DIR = os.path.join(
    "data",
    "rag",
    "mitre",
    "embeddings"
)

EMBEDDINGS_FILE = os.path.join(
    OUTPUT_DIR,
    "mitre_embeddings.npy"
)

METADATA_FILE = os.path.join(
    OUTPUT_DIR,
    "mitre_embedding_metadata.json"
)


# ---------------------------------------------------------
# Embedding model
# ---------------------------------------------------------

MODEL_NAME = "all-MiniLM-L6-v2"


def main():

    print("=" * 60)
    print("MITRE ATT&CK EMBEDDING GENERATION")
    print("=" * 60)

    # -----------------------------------------------------
    # Check input
    # -----------------------------------------------------

    if not os.path.exists(INPUT_FILE):
        raise FileNotFoundError(
            f"MITRE chunks file not found:\n{INPUT_FILE}"
        )

    # -----------------------------------------------------
    # Load chunks
    # -----------------------------------------------------

    print("\nLoading chunks...")

    with open(INPUT_FILE, "r", encoding="utf-8") as f:
        chunks = json.load(f)

    print(f"Chunks loaded: {len(chunks):,}")

    if not chunks:
        raise ValueError("No chunks found.")

    # -----------------------------------------------------
    # Extract text
    # -----------------------------------------------------

    texts = [
        chunk["text"]
        for chunk in chunks
    ]

    # -----------------------------------------------------
    # Load model
    # -----------------------------------------------------

    print("\nLoading embedding provider...")
    provider = get_embedding_provider()
    print(f"Model: {provider.model_name}, Dimension: {provider.dimension}")

    # -----------------------------------------------------
    # Generate embeddings
    # -----------------------------------------------------

    print("\nGenerating embeddings...")
    embeddings = provider.embed_documents(
        texts,
        batch_size=25,
        show_progress=True,
    )

    # -----------------------------------------------------
    # Verify embeddings
    # -----------------------------------------------------

    print("\nEmbedding verification")
    print("-" * 60)

    print(f"Number of embeddings : {len(embeddings):,}")
    print(f"Embedding dimensions : {embeddings.shape[1]}")
    print(f"Embedding shape      : {embeddings.shape}")

    if len(embeddings) != len(chunks):
        raise ValueError(
            "Embedding count does not match chunk count."
        )

    if not np.isfinite(embeddings).all():
        raise ValueError(
            "Invalid NaN or infinite values found in embeddings."
        )

    # -----------------------------------------------------
    # Create output directory
    # -----------------------------------------------------

    os.makedirs(
        OUTPUT_DIR,
        exist_ok=True
    )

    # -----------------------------------------------------
    # Save embeddings
    # -----------------------------------------------------

    np.save(
        EMBEDDINGS_FILE,
        embeddings
    )

    # -----------------------------------------------------
    # Save metadata
    # -----------------------------------------------------

    metadata = []

    for index, chunk in enumerate(chunks):

        metadata.append({
            "embedding_index": index,
            "source": chunk["metadata"]["source"],
            "technique_id": chunk["metadata"]["technique_id"],
            "technique_name": chunk["metadata"]["technique_name"],
            "chunk_id": chunk["metadata"]["chunk_id"]
        })

    with open(
        METADATA_FILE,
        "w",
        encoding="utf-8"
    ) as f:

        json.dump(
            metadata,
            f,
            indent=2,
            ensure_ascii=False
        )

    # -----------------------------------------------------
    # Final summary
    # -----------------------------------------------------

    print("\n" + "=" * 60)
    print("EMBEDDING GENERATION COMPLETE")
    print("=" * 60)

    print(f"Chunks              : {len(chunks):,}")
    print(f"Embeddings          : {len(embeddings):,}")
    print(f"Dimensions          : {embeddings.shape[1]}")
    print(f"Embeddings saved to : {EMBEDDINGS_FILE}")
    print(f"Metadata saved to   : {METADATA_FILE}")

    print("=" * 60)


if __name__ == "__main__":
    main()