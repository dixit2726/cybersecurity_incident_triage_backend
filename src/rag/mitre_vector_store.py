import json
import os

import faiss
import numpy as np


# ---------------------------------------------------------
# Paths
# ---------------------------------------------------------

EMBEDDINGS_FILE = os.path.join(
    "data", "rag", "mitre", "embeddings",
    "mitre_embeddings.npy"
)

METADATA_FILE = os.path.join(
    "data", "rag", "mitre", "embeddings",
    "mitre_embedding_metadata.json"
)

CHUNKS_FILE = os.path.join(
    "data", "rag", "mitre", "chunks",
    "mitre_chunks.json"
)

OUTPUT_DIR = os.path.join(
    "data", "rag", "mitre", "vector_store"
)

INDEX_FILE = os.path.join(
    OUTPUT_DIR,
    "mitre.index"
)


def main():

    print("=" * 60)
    print("MITRE ATT&CK FAISS VECTOR STORE")
    print("=" * 60)

    # -----------------------------------------------------
    # Check files
    # -----------------------------------------------------

    for file in [
        EMBEDDINGS_FILE,
        METADATA_FILE,
        CHUNKS_FILE
    ]:
        if not os.path.exists(file):
            raise FileNotFoundError(
                f"Required file not found:\n{file}"
            )

    # -----------------------------------------------------
    # Load embeddings
    # -----------------------------------------------------

    print("\nLoading embeddings...")

    embeddings = np.load(
        EMBEDDINGS_FILE
    ).astype("float32")

    print(f"Embedding shape: {embeddings.shape}")

    # -----------------------------------------------------
    # Load metadata
    # -----------------------------------------------------

    print("\nLoading metadata...")

    with open(
        METADATA_FILE,
        "r",
        encoding="utf-8"
    ) as f:
        metadata = json.load(f)

    print(f"Metadata records: {len(metadata):,}")

    # -----------------------------------------------------
    # Load chunks
    # -----------------------------------------------------

    print("\nLoading chunks...")

    with open(
        CHUNKS_FILE,
        "r",
        encoding="utf-8"
    ) as f:
        chunks = json.load(f)

    print(f"Chunks: {len(chunks):,}")

    # -----------------------------------------------------
    # Validate alignment
    # -----------------------------------------------------

    if len(embeddings) != len(metadata):
        raise ValueError(
            "Embedding count does not match metadata count."
        )

    if len(embeddings) != len(chunks):
        raise ValueError(
            "Embedding count does not match chunk count."
        )

    # -----------------------------------------------------
    # Create FAISS index
    # -----------------------------------------------------

    dimension = embeddings.shape[1]

    print("\nCreating FAISS index...")
    print(f"Vector dimension: {dimension}")

    # Embeddings were normalized during generation.
    # Inner product therefore works as cosine similarity.
    index = faiss.IndexFlatIP(dimension)

    index.add(embeddings)

    # -----------------------------------------------------
    # Save index
    # -----------------------------------------------------

    os.makedirs(
        OUTPUT_DIR,
        exist_ok=True
    )

    faiss.write_index(
        index,
        INDEX_FILE
    )

    # -----------------------------------------------------
    # Verification
    # -----------------------------------------------------

    print("\n" + "=" * 60)
    print("VECTOR STORE CREATED")
    print("=" * 60)

    print(f"Vectors indexed : {index.ntotal:,}")
    print(f"Dimensions      : {dimension}")
    print(f"Index type      : IndexFlatIP")
    print(f"Index saved to  : {INDEX_FILE}")

    if index.ntotal != len(chunks):
        raise ValueError(
            "FAISS index size does not match chunks."
        )

    print("\nValidation: PASSED")
    print("=" * 60)


if __name__ == "__main__":
    main()