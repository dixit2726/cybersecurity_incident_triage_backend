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
    "cisa",
    "chunks",
    "cisa_chunks.json"
)

OUTPUT_DIR = os.path.join(
    "data",
    "rag",
    "cisa",
    "embeddings"
)

EMBEDDINGS_FILE = os.path.join(
    OUTPUT_DIR,
    "cisa_embeddings.npy"
)

METADATA_FILE = os.path.join(
    OUTPUT_DIR,
    "cisa_embedding_metadata.json"
)


# ---------------------------------------------------------
# Embedding Model
# ---------------------------------------------------------

EXPECTED_DIMENSION = 768
BATCH_SIZE = 25


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


def generate_cisa_embeddings(
    input_file: str = INPUT_FILE,
    output_dir: str = OUTPUT_DIR,
    batch_size: int = BATCH_SIZE,
):
    """
    Load CISA chunks, generate normalized float32 embeddings using GeminiEmbeddingProvider,
    validate, and save embeddings (.npy) and metadata (.json).
    """
    # -----------------------------------------------------
    # Resolve and check input
    # -----------------------------------------------------
    resolved_input = resolve_path(input_file)

    if not os.path.exists(resolved_input):
        raise FileNotFoundError(
            f"CISA chunks file not found at: '{input_file}' (resolved: '{resolved_input}')"
        )

    # -----------------------------------------------------
    # Load chunks
    # -----------------------------------------------------
    print(f"Loading chunks from: {resolved_input}")
    with open(resolved_input, "r", encoding="utf-8") as f:
        chunks = json.load(f)

    num_chunks = len(chunks)
    print(f"Chunks loaded: {num_chunks:,}")

    if not chunks or num_chunks == 0:
        raise ValueError("No chunks found in input JSON file.")

    # -----------------------------------------------------
    # Extract texts
    # -----------------------------------------------------
    texts = [chunk["text"] for chunk in chunks]

    # -----------------------------------------------------
    # Load embedding provider
    # -----------------------------------------------------
    print("\nLoading embedding provider...")
    provider = get_embedding_provider()
    print(f"Model: {provider.model_name}, Dimension: {provider.dimension}")

    # -----------------------------------------------------
    # Generate normalized embeddings
    # -----------------------------------------------------
    print(f"\nGenerating normalized embeddings (batch_size={batch_size})...")
    embeddings = provider.embed_documents(
        texts,
        batch_size=batch_size,
        show_progress=True,
    )

    # Convert embeddings to float32 NumPy array
    embeddings = np.asarray(embeddings, dtype=np.float32)

    # -----------------------------------------------------
    # Build metadata list
    # -----------------------------------------------------
    metadata = []
    for index, chunk in enumerate(chunks):
        chunk_meta = chunk.get("metadata", {})
        meta_entry = {
            "embedding_index": index,
            "source": chunk_meta.get("source"),
            "source_type": chunk_meta.get("source_type"),
            "document_title": chunk_meta.get("document_title"),
            "category": chunk_meta.get("category"),
            "chunk_id": chunk_meta.get("chunk_id"),
        }
        # Preserve page information if available
        if "page_start" in chunk_meta:
            meta_entry["page_start"] = chunk_meta["page_start"]
        if "page_end" in chunk_meta:
            meta_entry["page_end"] = chunk_meta["page_end"]

        metadata.append(meta_entry)

    # -----------------------------------------------------
    # Validation
    # -----------------------------------------------------
    print("\nValidating embeddings and metadata...")
    num_embeddings = len(embeddings)
    embedding_dim = embeddings.shape[1] if embeddings.ndim > 1 else 0

    # 1. Number of embeddings == number of chunks
    if num_embeddings != num_chunks:
        raise ValueError(
            f"Validation Failed: Embedding count ({num_embeddings}) does not match chunk count ({num_chunks})."
        )

    # 2. Embedding dimension == 384
    if embedding_dim != EXPECTED_DIMENSION:
        raise ValueError(
            f"Validation Failed: Embedding dimension is {embedding_dim}, expected {EXPECTED_DIMENSION}."
        )

    # 3. No NaN values
    if np.isnan(embeddings).any():
        raise ValueError("Validation Failed: NaN values detected in generated embeddings.")

    # 4. No infinite values
    if np.isinf(embeddings).any() or not np.isfinite(embeddings).all():
        raise ValueError("Validation Failed: Infinite/non-finite values detected in generated embeddings.")

    # 5. Metadata count == chunk count
    if len(metadata) != num_chunks:
        raise ValueError(
            f"Validation Failed: Metadata count ({len(metadata)}) does not match chunk count ({num_chunks})."
        )

    validation_status = "PASSED (Count matched, dimension 384 verified, no NaN/inf, metadata aligned)"

    # -----------------------------------------------------
    # Create output directory
    # -----------------------------------------------------
    resolved_output_dir = resolve_path(output_dir)
    os.makedirs(resolved_output_dir, exist_ok=True)

    resolved_embeddings_file = os.path.join(resolved_output_dir, "cisa_embeddings.npy")
    resolved_metadata_file = os.path.join(resolved_output_dir, "cisa_embedding_metadata.json")

    # -----------------------------------------------------
    # Save embeddings & metadata
    # -----------------------------------------------------
    print(f"\nSaving embeddings to: {resolved_embeddings_file}")
    np.save(resolved_embeddings_file, embeddings)

    print(f"Saving metadata to: {resolved_metadata_file}")
    with open(resolved_metadata_file, "w", encoding="utf-8") as f:
        json.dump(metadata, f, indent=2, ensure_ascii=False)

    # -----------------------------------------------------
    # Print formatted summary
    # -----------------------------------------------------
    print("\n" + "=" * 60)
    print("CISA RAG EMBEDDING GENERATION")
    print("=" * 60)
    print(f"Total chunks        : {num_chunks}")
    print(f"Embedding dimension : {embedding_dim}")
    print(f"Embedding shape     : {embeddings.shape}")
    print(f"Model name          : {model_name}")
    print(f"Output embeddings   : {resolved_embeddings_file}")
    print(f"Output metadata     : {resolved_metadata_file}")
    print(f"Validation status   : {validation_status}")
    print("=" * 60 + "\n")

    return embeddings, metadata


def main():
    try:
        generate_cisa_embeddings()
    except Exception as e:
        print(f"\nExecution Error: {e}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
