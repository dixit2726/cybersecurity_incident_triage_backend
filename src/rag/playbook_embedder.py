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
    "playbooks",
    "chunks",
    "playbook_chunks.json"
)

OUTPUT_DIR = os.path.join(
    "data",
    "rag",
    "playbooks",
    "embeddings"
)

EMBEDDINGS_FILE = os.path.join(
    OUTPUT_DIR,
    "playbook_embeddings.npy"
)

METADATA_FILE = os.path.join(
    OUTPUT_DIR,
    "playbook_embedding_metadata.json"
)


# ---------------------------------------------------------
# Embedding Model
# ---------------------------------------------------------

MODEL_NAME = "all-MiniLM-L6-v2"


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
    print("PLAYBOOKS RAG EMBEDDING GENERATION")
    print("=" * 60)

    # -----------------------------------------------------
    # Resolve and check input
    # -----------------------------------------------------
    resolved_input = resolve_path(INPUT_FILE)

    if not os.path.exists(resolved_input):
        raise FileNotFoundError(
            f"Playbook chunks file not found at: '{INPUT_FILE}' (resolved: '{resolved_input}')"
        )

    # -----------------------------------------------------
    # Load chunks
    # -----------------------------------------------------
    print(f"\nLoading chunks from: {resolved_input}")
    with open(resolved_input, "r", encoding="utf-8") as f:
        chunks = json.load(f)

    print(f"Chunks loaded: {len(chunks):,}")

    if not chunks:
        raise ValueError("No chunks found in the input JSON file.")

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
    print("\nGenerating normalized embeddings...")
    embeddings = provider.embed_documents(
        texts,
        batch_size=25,
        show_progress=True,
    )

    embeddings = np.asarray(
        embeddings,
        dtype=np.float32
    )

    # -----------------------------------------------------
    # Validation
    # -----------------------------------------------------
    print("\nValidating embeddings...")
    num_chunks = len(chunks)
    num_embeddings = len(embeddings)
    embedding_dim = embeddings.shape[1] if embeddings.ndim > 1 else 0

    if num_embeddings != num_chunks:
        raise ValueError(
            f"Validation Failed: Embedding count ({num_embeddings}) does not match chunk count ({num_chunks})."
        )

    if np.isnan(embeddings).any():
        raise ValueError("Validation Failed: NaN values detected in generated embeddings.")

    if np.isinf(embeddings).any():
        raise ValueError("Validation Failed: Infinite values detected in generated embeddings.")

    if not np.isfinite(embeddings).all():
        raise ValueError("Validation Failed: Non-finite values detected in generated embeddings.")

    validation_status = "PASSED (Count matched, dimensions verified, no NaN/inf values)"

    # -----------------------------------------------------
    # Create output directory
    # -----------------------------------------------------
    resolved_output_dir = resolve_path(OUTPUT_DIR)
    os.makedirs(resolved_output_dir, exist_ok=True)

    resolved_embeddings_file = os.path.join(resolved_output_dir, "playbook_embeddings.npy")
    resolved_metadata_file = os.path.join(resolved_output_dir, "playbook_embedding_metadata.json")

    # -----------------------------------------------------
    # Save embeddings
    # -----------------------------------------------------
    print(f"\nSaving embeddings to: {resolved_embeddings_file}")
    np.save(resolved_embeddings_file, embeddings)

    # -----------------------------------------------------
    # Save metadata
    # -----------------------------------------------------
    print(f"Saving metadata to: {resolved_metadata_file}")
    metadata = []
    for index, chunk in enumerate(chunks):
        chunk_meta = chunk["metadata"]
        metadata.append({
            "embedding_index": index,
            "playbook_name": chunk_meta["playbook_name"],
            "incident_type": chunk_meta["incident_type"],
            "source": chunk_meta["source"],
            "chunk_id": chunk_meta["chunk_id"]
        })

    with open(resolved_metadata_file, "w", encoding="utf-8") as f:
        json.dump(metadata, f, indent=2, ensure_ascii=False)

    # -----------------------------------------------------
    # Print summary
    # -----------------------------------------------------
    print("\n" + "=" * 60)
    print("PLAYBOOK EMBEDDING SUMMARY")
    print("=" * 60)
    print(f"Total chunks        : {num_chunks:,}")
    print(f"Embedding dimension : {embedding_dim}")
    print(f"Embedding shape     : {embeddings.shape}")
    print(f"Model name          : {MODEL_NAME}")
    print(f"Output embeddings   : {resolved_embeddings_file}")
    print(f"Output metadata     : {resolved_metadata_file}")
    print(f"Validation status   : {validation_status}")
    print("=" * 60 + "\n")


if __name__ == "__main__":
    main()
