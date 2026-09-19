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
    "data", "rag", "cisa", "embeddings",
    "cisa_embeddings.npy"
)

METADATA_FILE = os.path.join(
    "data", "rag", "cisa", "embeddings",
    "cisa_embedding_metadata.json"
)

CHUNKS_FILE = os.path.join(
    "data", "rag", "cisa", "chunks",
    "cisa_chunks.json"
)

OUTPUT_DIR = os.path.join(
    "data", "rag", "cisa", "vector_store"
)

INDEX_FILE = os.path.join(
    OUTPUT_DIR,
    "cisa.index"
)

EXPECTED_DIMENSION = 384


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


def create_cisa_vector_store(
    embeddings_file: str = EMBEDDINGS_FILE,
    metadata_file: str = METADATA_FILE,
    chunks_file: str = CHUNKS_FILE,
    output_dir: str = OUTPUT_DIR,
    index_file: str = INDEX_FILE,
):
    """
    Load CISA embeddings, metadata, and chunks; validate alignment and integrity;
    create faiss.IndexFlatIP(384) index; add vectors; save to cisa.index and verify.
    """
    # -----------------------------------------------------
    # Resolve and check required input files
    # -----------------------------------------------------
    resolved_embeddings_file = resolve_path(embeddings_file)
    resolved_metadata_file = resolve_path(metadata_file)
    resolved_chunks_file = resolve_path(chunks_file)

    for file_path in [
        resolved_embeddings_file,
        resolved_metadata_file,
        resolved_chunks_file,
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
    print("\nValidating data integrity and alignment...")

    if num_embeddings != num_metadata:
        raise ValueError(
            f"Validation Failure: Number of embeddings ({num_embeddings}) != metadata records ({num_metadata})"
        )

    if num_metadata != num_chunks:
        raise ValueError(
            f"Validation Failure: Number of metadata records ({num_metadata}) != chunks ({num_chunks})"
        )

    if embedding_dim != EXPECTED_DIMENSION:
        raise ValueError(
            f"Validation Failure: Embedding dimension ({embedding_dim}) != expected dimension ({EXPECTED_DIMENSION})"
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
    # Embeddings are normalized, so Inner Product corresponds to cosine similarity.
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
    resolved_output_dir = resolve_path(output_dir)
    os.makedirs(resolved_output_dir, exist_ok=True)
    resolved_index_file = os.path.join(resolved_output_dir, os.path.basename(index_file))

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
    print("CISA FAISS VECTOR STORE")
    print("=" * 60)
    print(f"Embeddings loaded   : {resolved_embeddings_file}")
    print(f"Embedding count     : {num_embeddings}")
    print(f"Embedding dimension : {embedding_dim}")
    print(f"Metadata count      : {num_metadata}")
    print(f"Chunk count         : {num_chunks}")
    print(f"FAISS index type    : IndexFlatIP (Cosine Similarity)")
    print(f"Vectors added       : {vectors_added}")
    print(f"Index total         : {loaded_index.ntotal}")
    print(f"Validation status   : {validation_status}")
    print(f"Output file         : {resolved_index_file}")
    print("=" * 60 + "\n")

    return loaded_index


def main():
    try:
        create_cisa_vector_store()
    except Exception as e:
        print(f"\nExecution Error: {e}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
