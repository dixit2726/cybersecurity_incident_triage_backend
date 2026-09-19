import json
import os
import re
import sys

try:
    from langchain_text_splitters import RecursiveCharacterTextSplitter
except ImportError:
    try:
        from langchain.text_splitter import RecursiveCharacterTextSplitter
    except ImportError:
        raise ImportError(
            "RecursiveCharacterTextSplitter could not be imported. "
            "Please ensure 'langchain-text-splitters' or 'langchain' is installed."
        )


DEFAULT_INPUT_DIR = os.path.join(
    "data",
    "rag",
    "mitre",
    "processed"
)

DEFAULT_OUTPUT_DIR = os.path.join(
    "data",
    "rag",
    "mitre",
    "chunks"
)

DEFAULT_OUTPUT_FILE = os.path.join(
    DEFAULT_OUTPUT_DIR,
    "mitre_chunks.json"
)


def resolve_directory(path: str) -> str:
    """
    Resolve directory path relative to current working directory or project root.
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


def extract_technique_info(content: str, filename: str):
    """
    Extract technique_id and technique_name from the document header.
    Falls back to parsing the filename if headers are missing.
    """
    technique_id = None
    technique_name = None

    # Header regex extraction
    id_match = re.search(r"^Technique ID:\s*(.+)$", content, re.MULTILINE)
    if id_match:
        technique_id = id_match.group(1).strip()

    name_match = re.search(r"^Technique Name:\s*(.+)$", content, re.MULTILINE)
    if name_match:
        technique_name = name_match.group(1).strip()

    # Fallback to filename format: <ID>_<Name>.txt
    if not technique_id or not technique_name:
        base_name = os.path.splitext(filename)[0]
        parts = base_name.split("_", 1)
        if not technique_id and len(parts) > 0:
            technique_id = parts[0]
        if not technique_name and len(parts) > 1:
            technique_name = parts[1].replace("_", " ")

    return (
        technique_id or "Unknown",
        technique_name or "Unknown"
    )


def chunk_mitre_documents(
    input_dir: str = DEFAULT_INPUT_DIR,
    output_file: str = DEFAULT_OUTPUT_FILE,
    chunk_size: int = 1200,
    chunk_overlap: int = 150
):
    """
    Read all processed MITRE ATT&CK text files, split them using
    RecursiveCharacterTextSplitter, and save chunks with metadata to JSON.
    """
    resolved_input = resolve_directory(input_dir)

    if not os.path.exists(resolved_input):
        print(f"Error: Input directory not found at '{input_dir}' (resolved: '{resolved_input}').", file=sys.stderr)
        return False

    # Get list of .txt files
    txt_files = [f for f in sorted(os.listdir(resolved_input)) if f.endswith(".txt")]

    if not txt_files:
        print(f"Error: No .txt files found in '{resolved_input}'.", file=sys.stderr)
        return False

    # Initialize LangChain RecursiveCharacterTextSplitter
    text_splitter = RecursiveCharacterTextSplitter(
        chunk_size=chunk_size,
        chunk_overlap=chunk_overlap
    )

    all_chunks = []
    source_count = 0

    for filename in txt_files:
        file_path = os.path.join(resolved_input, filename)
        try:
            with open(file_path, "r", encoding="utf-8") as f:
                content = f.read()
        except Exception as e:
            print(f"Warning: Failed to read '{filename}': {e}", file=sys.stderr)
            continue

        source_count += 1
        technique_id, technique_name = extract_technique_info(content, filename)

        # Split document into chunks
        raw_chunks = text_splitter.split_text(content)

        # Build chunk dictionaries with metadata
        for chunk_id, chunk_text in enumerate(raw_chunks):
            all_chunks.append({
                "text": chunk_text,
                "metadata": {
                    "source": filename,
                    "technique_id": technique_id,
                    "technique_name": technique_name,
                    "chunk_id": chunk_id
                }
            })

    # Ensure output directory exists
    output_dir = os.path.dirname(output_file)
    if output_dir:
        os.makedirs(output_dir, exist_ok=True)

    # Save to JSON
    try:
        with open(output_file, "w", encoding="utf-8") as f:
            json.dump(all_chunks, f, indent=2, ensure_ascii=False)
    except Exception as e:
        print(f"Error: Failed to save chunks to '{output_file}': {e}", file=sys.stderr)
        return False

    total_chunks = len(all_chunks)
    avg_chunks = (total_chunks / source_count) if source_count > 0 else 0.0

    # Print summary
    print("\nMITRE ATT&CK CHUNKING SUMMARY")
    print("=============================")
    print(f"Number of source documents : {source_count}")
    print(f"Total chunks created       : {total_chunks}")
    print(f"Average chunks per document: {avg_chunks:.2f}")
    print(f"Output saved to            : {output_file}")
    print("=============================\n")

    # Print first 3 chunks with their metadata
    print("FIRST 3 CHUNKS PREVIEW")
    print("======================")
    for i, chunk in enumerate(all_chunks[:3], start=1):
        meta = chunk["metadata"]
        preview_text = chunk["text"]
        if len(preview_text) > 250:
            preview_text = preview_text[:250] + "..."

        print(f"--- Chunk {i} ---")
        print(f"Metadata:")
        print(f"  Source        : {meta['source']}")
        print(f"  Technique ID  : {meta['technique_id']}")
        print(f"  Technique Name: {meta['technique_name']}")
        print(f"  Chunk ID      : {meta['chunk_id']}")
        print(f"Text Content (preview):")
        print(f"{preview_text}\n")

    return True


def main():
    chunk_mitre_documents()


if __name__ == "__main__":
    main()
