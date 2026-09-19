import json
import os
import shutil
import sys
import numpy as np
import faiss
import time

# Ensure project root is in sys.path
PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from src.rag.embedding_provider import get_embedding_provider, normalize_vectors


def backup_file(src_path: str, backup_dir: str):
    """Safely back up a file before replacing it."""
    if os.path.exists(src_path):
        os.makedirs(backup_dir, exist_ok=True)
        dest = os.path.join(backup_dir, os.path.basename(src_path))
        if not os.path.exists(dest):
            shutil.copy2(src_path, dest)
            print(f"Backed up {src_path} -> {dest}")


def build_faiss_index(embeddings: np.ndarray, index_path: str):
    """Create and write an IndexFlatIP index for normalized embeddings."""
    dim = embeddings.shape[1]
    index = faiss.IndexFlatIP(dim)
    index.add(embeddings)
    os.makedirs(os.path.dirname(index_path), exist_ok=True)
    faiss.write_index(index, index_path)
    return index


def embed_chunks_with_checkpoint(texts, emb_file, provider, batch_size=20):
    """Embed chunks in batches with disk checkpointing so progress is never lost."""
    total = len(texts)
    dim = provider.dimension

    if os.path.exists(emb_file):
        try:
            loaded = np.load(emb_file)
            if loaded.shape == (total, dim):
                print(f"Found completed embeddings file {emb_file} with shape {loaded.shape}. Reusing.", flush=True)
                return loaded
            elif loaded.shape[1] == dim and loaded.shape[0] < total:
                print(f"Found partial embeddings file with {loaded.shape[0]}/{total} vectors. Resuming.", flush=True)
                all_vectors = list(loaded)
            else:
                all_vectors = []
        except Exception:
            all_vectors = []
    else:
        all_vectors = []

    start_idx = len(all_vectors)
    for i in range(start_idx, total, batch_size):
        batch = texts[i : i + batch_size]
        vecs = provider.embed_documents(batch, batch_size=batch_size, show_progress=False, rate_limit_pause=0.5)
        all_vectors.extend(vecs)
        time.sleep(1.0)

        pct = (len(all_vectors) / total) * 100.0
        print(f"Embedded {len(all_vectors):,}/{total:,} chunks ({pct:.1f}%)...", flush=True)

        # Save checkpoint
        temp_arr = np.asarray(all_vectors, dtype=np.float32)
        np.save(emb_file, temp_arr)

    final_arr = np.asarray(all_vectors, dtype=np.float32)
    final_arr = normalize_vectors(final_arr)
    np.save(emb_file, final_arr)
    return final_arr


def rebuild_playbooks(provider):
    print("\n" + "=" * 60)
    print("REBUILDING PLAYBOOKS FAISS INDEX")
    print("=" * 60)

    chunks_file = os.path.join(PROJECT_ROOT, "data", "rag", "playbooks", "chunks", "playbook_chunks.json")
    emb_dir = os.path.join(PROJECT_ROOT, "data", "rag", "playbooks", "embeddings")
    vec_dir = os.path.join(PROJECT_ROOT, "data", "rag", "playbooks", "vector_store")
    backup_dir = os.path.join(PROJECT_ROOT, "data", "rag", "playbooks", "backup_minilm")

    emb_file = os.path.join(emb_dir, "playbook_embeddings.npy")
    meta_file = os.path.join(emb_dir, "playbook_embedding_metadata.json")
    index_file = os.path.join(vec_dir, "playbooks.index")

    backup_file(emb_file, backup_dir)
    backup_file(meta_file, backup_dir)
    backup_file(index_file, backup_dir)

    with open(chunks_file, "r", encoding="utf-8") as f:
        chunks = json.load(f)

    texts = [c["text"] for c in chunks]
    embeddings = embed_chunks_with_checkpoint(texts, emb_file, provider, batch_size=25)

    metadata = []
    for idx, c in enumerate(chunks):
        metadata.append({
            "embedding_index": idx,
            "playbook_name": c["metadata"].get("playbook_name", ""),
            "incident_type": c["metadata"].get("incident_type", ""),
            "source": c["metadata"].get("source", ""),
            "chunk_id": c["metadata"].get("chunk_id", ""),
        })

    with open(meta_file, "w", encoding="utf-8") as f:
        json.dump(metadata, f, indent=2, ensure_ascii=False)

    index = build_faiss_index(embeddings, index_file)
    print(f"Playbooks index complete: {index.ntotal} vectors in {index_file}")


def rebuild_cisa(provider):
    print("\n" + "=" * 60)
    print("REBUILDING CISA GUIDANCE FAISS INDEX")
    print("=" * 60)

    chunks_file = os.path.join(PROJECT_ROOT, "data", "rag", "cisa", "chunks", "cisa_chunks.json")
    emb_dir = os.path.join(PROJECT_ROOT, "data", "rag", "cisa", "embeddings")
    vec_dir = os.path.join(PROJECT_ROOT, "data", "rag", "cisa", "vector_store")
    backup_dir = os.path.join(PROJECT_ROOT, "data", "rag", "cisa", "backup_minilm")

    emb_file = os.path.join(emb_dir, "cisa_embeddings.npy")
    meta_file = os.path.join(emb_dir, "cisa_embedding_metadata.json")
    index_file = os.path.join(vec_dir, "cisa.index")

    backup_file(emb_file, backup_dir)
    backup_file(meta_file, backup_dir)
    backup_file(index_file, backup_dir)

    with open(chunks_file, "r", encoding="utf-8") as f:
        chunks = json.load(f)

    texts = [c["text"] for c in chunks]
    embeddings = embed_chunks_with_checkpoint(texts, emb_file, provider, batch_size=20)

    metadata = []
    for idx, c in enumerate(chunks):
        entry = {
            "embedding_index": idx,
            "document_title": c["metadata"].get("document_title", ""),
            "category": c["metadata"].get("category", ""),
            "source_type": c["metadata"].get("source_type", ""),
            "source": c["metadata"].get("source", ""),
            "chunk_id": c["metadata"].get("chunk_id", ""),
        }
        if "page_start" in c["metadata"]:
            entry["page_start"] = c["metadata"]["page_start"]
        if "page_end" in c["metadata"]:
            entry["page_end"] = c["metadata"]["page_end"]
        metadata.append(entry)

    with open(meta_file, "w", encoding="utf-8") as f:
        json.dump(metadata, f, indent=2, ensure_ascii=False)

    index = build_faiss_index(embeddings, index_file)
    print(f"CISA index complete: {index.ntotal} vectors in {index_file}")


def rebuild_mitre(provider):
    print("\n" + "=" * 60)
    print("REBUILDING MITRE ATT&CK FAISS INDEX")
    print("=" * 60)

    chunks_file = os.path.join(PROJECT_ROOT, "data", "rag", "mitre", "chunks", "mitre_chunks.json")
    emb_dir = os.path.join(PROJECT_ROOT, "data", "rag", "mitre", "embeddings")
    vec_dir = os.path.join(PROJECT_ROOT, "data", "rag", "mitre", "vector_store")
    backup_dir = os.path.join(PROJECT_ROOT, "data", "rag", "mitre", "backup_minilm")

    emb_file = os.path.join(emb_dir, "mitre_embeddings.npy")
    meta_file = os.path.join(emb_dir, "mitre_embedding_metadata.json")
    index_file = os.path.join(vec_dir, "mitre.index")

    backup_file(emb_file, backup_dir)
    backup_file(meta_file, backup_dir)
    backup_file(index_file, backup_dir)

    with open(chunks_file, "r", encoding="utf-8") as f:
        chunks = json.load(f)

    texts = [c["text"] for c in chunks]
    embeddings = embed_chunks_with_checkpoint(texts, emb_file, provider, batch_size=20)

    metadata = []
    for idx, c in enumerate(chunks):
        metadata.append({
            "embedding_index": idx,
            "source": c["metadata"].get("source", "enterprise-attack.json"),
            "technique_id": c["metadata"].get("technique_id", ""),
            "technique_name": c["metadata"].get("technique_name", ""),
            "chunk_id": c["metadata"].get("chunk_id", ""),
        })

    with open(meta_file, "w", encoding="utf-8") as f:
        json.dump(metadata, f, indent=2, ensure_ascii=False)

    index = build_faiss_index(embeddings, index_file)
    print(f"MITRE index complete: {index.ntotal} vectors in {index_file}")


def main():
    provider = get_embedding_provider()
    print("Using Embedding Provider: %s, Dimension: %d" % (provider.model_name, provider.dimension))

    rebuild_playbooks(provider)
    rebuild_cisa(provider)
    rebuild_mitre(provider)

    print("\n" + "=" * 60)
    print("ALL THREE FAISS INDEXES REBUILT SUCCESSFULLY!")
    print("=" * 60)


if __name__ == "__main__":
    main()
