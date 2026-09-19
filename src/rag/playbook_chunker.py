import json
import os
import re
import sys

# Ensure project root is in sys.path
PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

try:
    from langchain_text_splitters import RecursiveCharacterTextSplitter
except ImportError:
    try:
        from langchain.text_splitter import RecursiveCharacterTextSplitter
    except ImportError:
        raise ImportError(
            "RecursiveCharacterTextSplitter could not be imported. "
            "Please install 'langchain-text-splitters' or 'langchain'."
        )


DEFAULT_INPUT_DIR = os.path.join(
    "data",
    "rag",
    "playbooks"
)

DEFAULT_OUTPUT_DIR = os.path.join(
    "data",
    "rag",
    "playbooks",
    "chunks"
)

DEFAULT_OUTPUT_FILE = os.path.join(
    DEFAULT_OUTPUT_DIR,
    "playbook_chunks.json"
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


def extract_metadata(content: str, filename: str):
    """
    Extract playbook_name and incident_type from Markdown content.
    """
    playbook_name = None
    incident_type = None

    # Extract title: "# Playbook: <name>"
    title_match = re.search(r"^#\s*Playbook:\s*(.+)$", content, re.MULTILINE)
    if title_match:
        playbook_name = title_match.group(1).strip()
    else:
        playbook_name = os.path.splitext(filename)[0].replace("_", " ").title()

    # Extract incident type: "## Incident Type\n<type>"
    incident_match = re.search(
        r"^##\s*Incident Type\s*\n+([^\n#]+)",
        content,
        re.MULTILINE
    )
    if incident_match:
        incident_type = incident_match.group(1).strip()
    else:
        incident_type = "Unknown"

    return playbook_name, incident_type


def chunk_playbooks(
    input_dir: str = DEFAULT_INPUT_DIR,
    output_file: str = DEFAULT_OUTPUT_FILE,
    chunk_size: int = 1200,
    chunk_overlap: int = 150
):
    """
    Read all Markdown playbooks, chunk them preserving section boundaries,
    attach metadata, validate output, and save to JSON.
    """
    resolved_input = resolve_path(input_dir)

    if not os.path.exists(resolved_input):
        raise FileNotFoundError(
            f"Input directory not found at '{input_dir}' (resolved: '{resolved_input}')."
        )

    # List all .md files in the input directory (excluding subdirectories)
    md_files = [
        f for f in sorted(os.listdir(resolved_input))
        if f.endswith(".md") and os.path.isfile(os.path.join(resolved_input, f))
    ]

    if not md_files:
        raise FileNotFoundError(
            f"No Markdown (.md) files found in '{resolved_input}'."
        )

    # Validation: Confirm that 6 Markdown files were found
    if len(md_files) != 6:
        print(
            f"Warning: Expected 6 playbook files, but found {len(md_files)} in '{resolved_input}'.",
            file=sys.stderr
        )
    else:
        print(f"Verified: Successfully found all 6 playbook Markdown files in '{resolved_input}'.")

    # Configure RecursiveCharacterTextSplitter with section-aware separators
    text_splitter = RecursiveCharacterTextSplitter(
        chunk_size=chunk_size,
        chunk_overlap=chunk_overlap,
        separators=[
            "\n## ",
            "\n### ",
            "\n\n",
            "\n",
            " ",
            ""
        ]
    )

    all_chunks = []
    processed_files_count = 0

    for filename in md_files:
        file_path = os.path.join(resolved_input, filename)
        with open(file_path, "r", encoding="utf-8") as f:
            content = f.read()

        if not content.strip():
            print(f"Warning: '{filename}' is empty. Skipping.", file=sys.stderr)
            continue

        processed_files_count += 1
        playbook_name, incident_type = extract_metadata(content, filename)

        # Split the playbook into chunks
        raw_chunks = text_splitter.split_text(content)

        for chunk_id, chunk_text in enumerate(raw_chunks):
            # Clean leading/trailing whitespace while preserving structure
            cleaned_text = chunk_text.strip()
            if not cleaned_text:
                continue

            all_chunks.append({
                "text": cleaned_text,
                "metadata": {
                    "playbook_name": playbook_name,
                    "incident_type": incident_type,
                    "source": filename,
                    "chunk_id": chunk_id
                }
            })

    # -------------------------------------------------------------
    # Validations
    # -------------------------------------------------------------
    if processed_files_count != 6:
        raise ValueError(
            f"Validation failure: Expected 6 files to be processed, but processed {processed_files_count}."
        )

    if not all_chunks:
        raise ValueError(
            "Validation failure: No chunks were created."
        )

    empty_chunks = [c for c in all_chunks if not c.get("text", "").strip()]
    if empty_chunks:
        raise ValueError(
            f"Validation failure: Found {len(empty_chunks)} chunks with empty text."
        )

    # -------------------------------------------------------------
    # Save output
    # -------------------------------------------------------------
    output_dir = os.path.dirname(output_file)
    if output_dir:
        os.makedirs(output_dir, exist_ok=True)

    with open(output_file, "w", encoding="utf-8") as f:
        json.dump(all_chunks, f, indent=2, ensure_ascii=False)

    total_documents = processed_files_count
    total_chunks = len(all_chunks)
    avg_chunks = (total_chunks / total_documents) if total_documents > 0 else 0.0

    # -------------------------------------------------------------
    # Summary & Preview
    # -------------------------------------------------------------
    print("\n" + "=" * 60)
    print("PLAYBOOKS RAG CHUNKING SUMMARY")
    print("=" * 60)
    print(f"Total documents loaded       : {total_documents}")
    print(f"Total chunks created         : {total_chunks}")
    print(f"Average chunks per playbook  : {avg_chunks:.2f}")
    print(f"Output directory             : {output_dir}")
    print(f"Output JSON file             : {output_file}")
    print("=" * 60 + "\n")

    print("FIRST 3 CHUNKS PREVIEW")
    print("=" * 60)
    for i, chunk in enumerate(all_chunks[:3], start=1):
        meta = chunk["metadata"]
        preview_text = (
            chunk["text"][:250].replace("\n", " ") + "..."
            if len(chunk["text"]) > 250
            else chunk["text"].replace("\n", " ")
        )
        print(f"\n[Chunk {i}]")
        print(f"Playbook Name : {meta['playbook_name']}")
        print(f"Incident Type : {meta['incident_type']}")
        print(f"Source        : {meta['source']}")
        print(f"Chunk ID      : {meta['chunk_id']}")
        print(f"Text Preview  : {preview_text}")

    print("\n" + "=" * 60)
    print("PLAYBOOKS CHUNKING COMPLETE")
    print("=" * 60 + "\n")

    return all_chunks


def main():
    try:
        chunk_playbooks()
    except Exception as e:
        print(f"\nExecution Error: {e}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
