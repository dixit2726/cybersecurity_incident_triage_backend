import json
import math
import os
import re
import sys
from typing import Any, Dict, List, Optional, Tuple

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
            "Please ensure 'langchain-text-splitters' or 'langchain' is installed."
        )

try:
    import pypdf
except ImportError:
    raise ImportError(
        "pypdf could not be imported. Please ensure 'pypdf' is installed."
    )


DEFAULT_INPUT_DIR = os.path.join("data", "rag", "cisa")
DEFAULT_OUTPUT_DIR = os.path.join("data", "rag", "cisa", "chunks")
DEFAULT_OUTPUT_FILE = os.path.join(DEFAULT_OUTPUT_DIR, "cisa_chunks.json")

EXPECTED_DOC_COUNT = 7
EXPECTED_CATEGORIES = {
    "incident_response",
    "ransomware",
    "logging",
    "network_visibility",
    "advisories",
}


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


def discover_cisa_documents(base_dir: str) -> List[Tuple[str, str, str]]:
    """
    Recursively discover .pdf and .md documents under base_dir.
    Excludes the chunks output directory.
    Returns list of tuples: (full_path, category, source_type).
    """
    resolved_base = resolve_path(base_dir)
    if not os.path.exists(resolved_base):
        raise FileNotFoundError(
            f"Base directory does not exist: {resolved_base}"
        )

    discovered = []
    output_dir_resolved = os.path.abspath(os.path.join(resolved_base, "chunks"))

    for root, dirs, files in os.walk(resolved_base):
        # Do not descend into 'chunks' directory
        dirs[:] = [d for d in dirs if os.path.abspath(os.path.join(root, d)) != output_dir_resolved and d != "chunks"]

        for file in files:
            ext = os.path.splitext(file)[1].lower()
            if ext in [".pdf", ".md"]:
                full_path = os.path.join(root, file)
                rel_path = os.path.relpath(full_path, resolved_base)
                parts = rel_path.replace("\\", "/").split("/")

                if len(parts) >= 2:
                    category = parts[0]
                else:
                    category = "uncategorized"

                source_type = "pdf" if ext == ".pdf" else "markdown"
                discovered.append((full_path, category, source_type))

    # Sort for deterministic processing order
    discovered.sort(key=lambda x: (x[1], os.path.basename(x[0])))
    return discovered


def extract_markdown_title(content: str, filename: str) -> str:
    """
    Extract document title from Markdown content (# Heading).
    """
    match = re.search(r"^#\s+(.+)$", content, re.MULTILINE)
    if match:
        title = match.group(1).strip()
        # Clean potential markdown formatting
        title = re.sub(r"[*_`]", "", title)
        if title:
            return title

    # Fallback to base filename if no title heading found
    base_name = os.path.splitext(filename)[0]
    return base_name.replace("_", " ").title()


def extract_pdf_title(reader: pypdf.PdfReader, first_page_text: str, filename: str) -> str:
    """
    Extract title from PDF metadata or from first page content without inventing titles.
    """
    # 1. Check embedded PDF metadata title
    if reader.metadata and reader.metadata.title:
        meta_title = str(reader.metadata.title).strip()
        if meta_title and not meta_title.lower().startswith("untitled"):
            return meta_title

    # 2. Extract from known official CISA advisory headers on page 1
    # Check for Russian Foreign Intelligence Service advisory
    if "Russian Foreign Intelligence Service" in first_page_text:
        match = re.search(
            r"Russian Foreign Intelligence Service.*?\n.*?Exploiting JetBrains TeamCity CVE.*?(?:\n|$)",
            first_page_text,
            re.IGNORECASE,
        )
        if match:
            clean = " ".join(match.group(0).split())
            clean = clean.replace("Global ly", "Globally")
            return clean

    # Check for PRC State-Sponsored Actors advisory
    if "PRC State-Sponsored Actors" in first_page_text:
        match = re.search(
            r"PRC State-Sponsored Actors.*?Maintain Persistent Access to U\.S\. Critical\s+Infrastructure",
            first_page_text,
            re.DOTALL | re.IGNORECASE,
        )
        if match:
            clean = " ".join(match.group(0).split())
            return clean

    # Check for general title block following TLP / Co-Authored markings
    tlp_match = re.search(
        r"(?:TLP:(?:CLEAR|WHITE)|Co-Authored by:.*?)\s*\n+([A-Z0-9#][^\n]+(?:\n[A-Z0-9][^\n]+){0,2})\s*\n+(?:SUMMARY|THREAT OVERVIEW|Publication:)",
        first_page_text,
        re.DOTALL,
    )
    if tlp_match:
        cand = " ".join(tlp_match.group(1).split()).strip()
        if len(cand) > 5:
            return cand

    # Fallback directly derived from the document's official filename
    base_name = os.path.splitext(filename)[0]
    return base_name.replace("_", " ").title()


def extract_pdf_document(
    file_path: str,
) -> Tuple[str, str, List[Tuple[int, int, int]]]:
    """
    Extract text and page boundaries from PDF using pypdf.
    Returns (full_text, title, page_boundaries).
    page_boundaries contains list of (page_num, start_char, end_char).
    """
    try:
        reader = pypdf.PdfReader(file_path)
    except Exception as e:
        raise RuntimeError(f"Failed to read PDF file '{file_path}': {e}") from e

    num_pages = len(reader.pages)
    if num_pages == 0:
        raise ValueError(f"PDF document '{file_path}' has 0 pages.")

    filename = os.path.basename(file_path)
    full_text = ""
    page_boundaries = []

    for page_idx, page in enumerate(reader.pages, start=1):
        try:
            page_text = page.extract_text() or ""
        except Exception as e:
            raise RuntimeError(
                f"Error extracting text from page {page_idx} of '{file_path}': {e}"
            ) from e

        start_char = len(full_text)
        full_text += page_text + "\n\n"
        end_char = len(full_text)
        page_boundaries.append((page_idx, start_char, end_char))

    first_page_text = reader.pages[0].extract_text() or ""
    title = extract_pdf_title(reader, first_page_text, filename)

    return full_text, title, page_boundaries


def extract_markdown_document(
    file_path: str,
) -> Tuple[str, str]:
    """
    Read markdown file using UTF-8 and extract title.
    Returns (content, title).
    """
    filename = os.path.basename(file_path)
    try:
        with open(file_path, "r", encoding="utf-8") as f:
            content = f.read()
    except Exception as e:
        raise RuntimeError(f"Failed to read Markdown file '{file_path}': {e}") from e

    if not content.strip():
        raise ValueError(f"Markdown document '{file_path}' is empty.")

    title = extract_markdown_title(content, filename)
    return content, title


def determine_page_range(
    chunk_start: int,
    chunk_end: int,
    page_boundaries: List[Tuple[int, int, int]],
) -> Tuple[int, int]:
    """
    Determine (page_start, page_end) given character offsets and page boundaries.
    """
    p_start = None
    p_end = None

    for p_num, s_char, e_char in page_boundaries:
        if p_start is None and chunk_start < e_char:
            p_start = p_num
        if chunk_end <= e_char:
            p_end = p_num
            break

    if p_start is None:
        p_start = page_boundaries[0][0]
    if p_end is None:
        p_end = page_boundaries[-1][0]

    return p_start, p_end


def chunk_cisa_documents(
    input_dir: str = DEFAULT_INPUT_DIR,
    output_file: str = DEFAULT_OUTPUT_FILE,
    chunk_size: int = 1200,
    chunk_overlap: int = 150,
) -> List[Dict[str, Any]]:
    """
    Discover CISA documents, extract text, chunk with RecursiveCharacterTextSplitter,
    validate, and save to output_file.
    """
    resolved_input = resolve_path(input_dir)
    discovered_files = discover_cisa_documents(resolved_input)

    # Validation: Exactly 7 documents must be discovered
    if len(discovered_files) != EXPECTED_DOC_COUNT:
        raise ValueError(
            f"Validation Failure: Expected exactly {EXPECTED_DOC_COUNT} CISA documents, "
            f"but found {len(discovered_files)} under '{resolved_input}'."
        )

    text_splitter = RecursiveCharacterTextSplitter(
        chunk_size=chunk_size,
        chunk_overlap=chunk_overlap,
        separators=[
            "\n## ",
            "\n### ",
            "\n\n",
            "\n",
            ". ",
            " ",
            "",
        ],
    )

    all_chunks: List[Dict[str, Any]] = []
    doc_stats: List[Dict[str, Any]] = []
    pdf_count = 0
    md_count = 0

    for file_path, category, source_type in discovered_files:
        filename = os.path.basename(file_path)

        if category not in EXPECTED_CATEGORIES:
            raise ValueError(
                f"Unexpected category '{category}' for file '{filename}'. "
                f"Expected one of: {EXPECTED_CATEGORIES}"
            )

        if source_type == "pdf":
            pdf_count += 1
            full_text, title, page_boundaries = extract_pdf_document(file_path)
            raw_chunks = text_splitter.split_text(full_text)

            if not raw_chunks:
                raise ValueError(
                    f"Processing error: Document '{filename}' yielded 0 chunks."
                )

            # Search tracking for page boundaries
            search_pos = 0
            doc_chunk_count = 0

            for chunk_id, chunk_text in enumerate(raw_chunks):
                cleaned_text = chunk_text.strip()
                if not cleaned_text:
                    continue

                pos = full_text.find(chunk_text, max(0, search_pos - 200))
                if pos == -1:
                    pos = full_text.find(chunk_text)

                if pos != -1:
                    search_pos = pos
                    chunk_start = pos
                    chunk_end = pos + len(chunk_text)
                    page_start, page_end = determine_page_range(
                        chunk_start, chunk_end, page_boundaries
                    )
                else:
                    page_start = 1
                    page_end = 1

                chunk_record = {
                    "text": cleaned_text,
                    "metadata": {
                        "source": filename,
                        "source_type": source_type,
                        "document_title": title,
                        "category": category,
                        "chunk_id": chunk_id,
                        "page_start": page_start,
                        "page_end": page_end,
                    },
                }
                all_chunks.append(chunk_record)
                doc_chunk_count += 1

            if doc_chunk_count == 0:
                raise ValueError(
                    f"Document '{filename}' produced zero valid non-empty chunks."
                )

            doc_stats.append({
                "source": filename,
                "title": title,
                "category": category,
                "type": source_type,
                "chunks": doc_chunk_count,
            })

        elif source_type == "markdown":
            md_count += 1
            content, title = extract_markdown_document(file_path)
            raw_chunks = text_splitter.split_text(content)

            if not raw_chunks:
                raise ValueError(
                    f"Processing error: Document '{filename}' yielded 0 chunks."
                )

            doc_chunk_count = 0
            for chunk_id, chunk_text in enumerate(raw_chunks):
                cleaned_text = chunk_text.strip()
                if not cleaned_text:
                    continue

                chunk_record = {
                    "text": cleaned_text,
                    "metadata": {
                        "source": filename,
                        "source_type": source_type,
                        "document_title": title,
                        "category": category,
                        "chunk_id": chunk_id,
                    },
                }
                all_chunks.append(chunk_record)
                doc_chunk_count += 1

            if doc_chunk_count == 0:
                raise ValueError(
                    f"Document '{filename}' produced zero valid non-empty chunks."
                )

            doc_stats.append({
                "source": filename,
                "title": title,
                "category": category,
                "type": source_type,
                "chunks": doc_chunk_count,
            })

    # =============================================================
    # Strict Validations
    # =============================================================
    # 1. Exactly 7 source documents discovered and processed
    if len(doc_stats) != EXPECTED_DOC_COUNT:
        raise ValueError(
            f"Validation Failure: Expected {EXPECTED_DOC_COUNT} processed documents, "
            f"got {len(doc_stats)}."
        )

    # 2. No document produced zero chunks
    for stat in doc_stats:
        if stat["chunks"] <= 0:
            raise ValueError(
                f"Validation Failure: Document '{stat['source']}' has 0 chunks."
            )

    # 3. No chunk contains empty text
    empty_chunks = [c for c in all_chunks if not c.get("text", "").strip()]
    if empty_chunks:
        raise ValueError(
            f"Validation Failure: Found {len(empty_chunks)} chunks with empty text."
        )

    # 4. No NaN, None, or invalid metadata values
    for idx, c in enumerate(all_chunks):
        meta = c.get("metadata", {})
        required_keys = ["source", "source_type", "document_title", "category", "chunk_id"]
        for k in required_keys:
            val = meta.get(k)
            if val is None or val == "":
                raise ValueError(
                    f"Validation Failure: Chunk {idx} missing or empty metadata '{k}'."
                )
            if isinstance(val, float) and (math.isnan(val) or math.isinf(val)):
                raise ValueError(
                    f"Validation Failure: Chunk {idx} has invalid numerical metadata '{k}': {val}."
                )

    # =============================================================
    # Save Output
    # =============================================================
    resolved_output = resolve_path(output_file)
    output_dir = os.path.dirname(resolved_output)
    if output_dir:
        os.makedirs(output_dir, exist_ok=True)

    with open(resolved_output, "w", encoding="utf-8") as f:
        json.dump(all_chunks, f, indent=2, ensure_ascii=False)

    total_documents = len(doc_stats)
    total_chunks = len(all_chunks)
    avg_chunks = (total_chunks / total_documents) if total_documents > 0 else 0.0

    # =============================================================
    # Print Formatted Summary
    # =============================================================
    print("\n" + "=" * 60)
    print("CISA RAG CHUNKING SUMMARY")
    print("=" * 60)
    print(f"Total documents             : {total_documents}")
    print(f"PDF documents               : {pdf_count}")
    print(f"Markdown documents          : {md_count}")
    print(f"Total chunks                : {total_chunks}")
    print(f"Average chunks per document : {avg_chunks:.2f}")
    print(f"Output directory            : {output_dir}")
    print(f"Output JSON file            : {resolved_output}")
    print("\nDOCUMENT BREAKDOWN")
    print("-" * 60)
    for stat in doc_stats:
        print(f"- [{stat['category']}] ({stat['type'].upper()}) {stat['source']}")
        print(f"    Title  : {stat['title']}")
        print(f"    Chunks : {stat['chunks']}")
    print("-" * 60)

    # =============================================================
    # Print First 5 Chunks Preview
    # =============================================================
    print("\nFIRST 5 CHUNKS PREVIEW")
    print("=" * 60)
    for i, chunk in enumerate(all_chunks[:5], start=1):
        meta = chunk["metadata"]
        preview_text = (
            chunk["text"][:250].replace("\n", " ") + "..."
            if len(chunk["text"]) > 250
            else chunk["text"].replace("\n", " ")
        )
        print(f"\n[Chunk {i}]")
        print(f"Document Title : {meta['document_title']}")
        print(f"Category       : {meta['category']}")
        print(f"Source         : {meta['source']}")
        print(f"Chunk ID       : {meta['chunk_id']}")
        if "page_start" in meta:
            print(f"Pages          : {meta['page_start']} - {meta['page_end']}")
        print(f"Text Preview   : {preview_text}")

    print("\n" + "=" * 60)
    print("CISA CHUNKING COMPLETE")
    print("=" * 60 + "\n")

    return all_chunks


def main():
    try:
        chunk_cisa_documents()
    except Exception as e:
        print(f"\nExecution Error: {e}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
