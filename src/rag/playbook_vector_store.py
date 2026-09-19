import json
import os
import sys

import faiss
import numpy as np

# Ensure project root is in sys.path
PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)


# ---------------------------------------------------------
# Paths
# ---------------------------------------------------------

EMBEDDINGS_FILE = os.path.join(
    "data", "rag", "playbooks", "embeddings",
    "playbook_embeddings.npy"
)

METADATA_FILE = os.path.join(
    "data", "rag", "playbooks", "embeddings",
    "playbook_embedding_metadata.json"
)

CHUNKS_FILE = os.path.join(
    "data", "rag", "playbooks", "chunks",
    "playbook_chunks.json"
)

OUTPUT_DIR = os.path.join(
    "data", "rag", "playbooks", "vector_store"
)

INDEX_FILE = os.path.join(
    OUTPUT_DIR,
    "playbooks.index"
)


def resolve_path(path: str) -> str:
    """
    Resolve path relative to current working directory or project root.
    """
    if os.path.exists(path):
        return path

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

    return path


def main():
    print("=" * 60)
    print("PLAYBOOKS FAISS VECTOR STORE CREATION")
    print("=" * 60)

    # -----------------------------------------------------
    # Check required input files
    # -----------------------------------------------------
    resolved_embeddings_file = resolve_path(EMBEDDINGS_FILE)
    resolved_metadata_file = resolve_path(METADATA_FILE)
    resolved_chunks_file = resolve_path(CHUNKS_FILE)

    for file_path in [
        resolved_embeddings_file,
        resolved_metadata_file,
        resolved_chunks_file
    ]:
        if not os.path.exists(file_path):
            raise FileNotFoundError(f"Required file not found: {file_path}")

    # -----------------------------------------------------
    # 1. Load embeddings
    # -----------------------------------------------------
    print(f"\nLoading embeddings from: {resolved_embeddings_file}")
    embeddings = np.load(resolved_embeddings_file).astype("float32")
    num_embeddings = len(embeddings)
    embedding_dim = embeddings.shape[1] if embeddings.ndim > 1 else 0

    # -----------------------------------------------------
    # 2. Load metadata
    # -----------------------------------------------------
    print(f"Loading metadata from: {resolved_metadata_file}")
    with open(resolved_metadata_file, "r", encoding="utf-8") as f:
        metadata = json.load(f)
    num_metadata = len(metadata)

    # -----------------------------------------------------
    # 3. Load chunks
    # -----------------------------------------------------
    print(f"Loading chunks from: {resolved_chunks_file}")
    with open(resolved_chunks_file, "r", encoding="utf-8") as f:
        chunks = json.load(f)
    num_chunks = len(chunks)

    # -----------------------------------------------------
    # 4. Validations
    # -----------------------------------------------------
    print("\nValidating data integrity...")

    if num_embeddings != num_metadata:
        raise ValueError(
            f"Validation Failure: Number of embeddings ({num_embeddings}) != metadata records ({num_metadata})"
        )

    if num_metadata != num_chunks:
        raise ValueError(
            f"Validation Failure: Number of metadata records ({num_metadata}) != chunks ({num_chunks})"
        )

    if embedding_dim <= 0:
        raise ValueError(
            f"Validation Failure: Invalid embedding dimension ({embedding_dim})"
        )

    if np.isnan(embeddings).any():
        raise ValueError("Validation Failure: NaN values found in embeddings array.")

    if np.isinf(embeddings).any():
        raise ValueError("Validation Failure: Infinite values found in embeddings array.")

    if not np.isfinite(embeddings).all():
        raise ValueError("Validation Failure: Non-finite values found in embeddings array.")

    validation_status = "PASSED (Integrity, alignment, and numerical checks verified)"

    # -----------------------------------------------------
    # 5. Create FAISS index
    # -----------------------------------------------------
    # Embeddings were L2-normalized during generation by SentenceTransformer.
    # In normalized vector space, Inner Product (IndexFlatIP) is mathematically
    # identical to Cosine Similarity (A . B = ||A|| * ||B|| * cos(theta) = cos(theta)).
    print(f"\nInitializing FAISS IndexFlatIP with dimension {embedding_dim}...")
    index = faiss.IndexFlatIP(embedding_dim)

    # -----------------------------------------------------
    # 6. Add embeddings to index
    # -----------------------------------------------------
    index.add(embeddings)
    vectors_added = index.ntotal

    # -----------------------------------------------------
    # 7. Create output directory
    # -----------------------------------------------------
    resolved_output_dir = resolve_path(OUTPUT_DIR)
    os.makedirs(resolved_output_dir, exist_ok=True)
    resolved_index_file = os.path.join(resolved_output_dir, "playbooks.index")

    # -----------------------------------------------------
    # 8. Save FAISS index
    # -----------------------------------------------------
    print(f"Saving FAISS index to: {resolved_index_file}")
    faiss.write_index(index, resolved_index_file)

    # -----------------------------------------------------
    # 9. Verify saved index
    # -----------------------------------------------------
    loaded_index = faiss.read_index(resolved_index_file)
    if loaded_index.ntotal != num_embeddings:
        raise ValueError(
            f"Index verification failed: saved index total ({loaded_index.ntotal}) != number of embeddings ({num_embeddings})"
        )

    # -----------------------------------------------------
    # 10. Print summary
    # -----------------------------------------------------
    print("\n" + "=" * 60)
    print("PLAYBOOKS FAISS VECTOR STORE")
    print("=" * 60)
    print(f"Embeddings loaded   : {resolved_embeddings_file}")
    print(f"Embedding count     : {num_embeddings:,}")
    print(f"Embedding dimension : {embedding_dim}")
    print(f"Metadata count      : {num_metadata:,}")
    print(f"Chunk count         : {num_chunks:,}")
    print(f"FAISS index type    : IndexFlatIP (Cosine Similarity)")
    print(f"Vectors added       : {vectors_added:,}")
    print(f"Index total         : {loaded_index.ntotal:,}")
    print(f"Validation status   : {validation_status}")
    print(f"Output file         : {resolved_index_file}")
    print("=" * 60 + "\n")


if __name__ == "__main__":
    main()
