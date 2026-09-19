import html
import json
import os
import re
import sys


DEFAULT_INPUT_PATH = os.path.join(
    "data",
    "rag",
    "mitre",
    "enterprise-attack-19.2.json"
)

DEFAULT_OUTPUT_DIR = os.path.join(
    "data",
    "rag",
    "mitre",
    "processed"
)


def resolve_input_path(input_path: str = DEFAULT_INPUT_PATH) -> str:
    """
    Resolve input file path relative to current working directory, project root,
    or fallback locations.
    """
    if os.path.exists(input_path):
        return input_path

    # Check relative to script directory
    script_relative = os.path.abspath(
        os.path.join(
            os.path.dirname(__file__),
            "..",
            "..",
            input_path
        )
    )
    if os.path.exists(script_relative):
        return script_relative

    # Check external location fallback if available
    external_fallback = os.path.join("data", "external", "mitre", "enterprise-attack.json")
    if os.path.exists(external_fallback):
        return external_fallback

    return input_path


def sanitize_filename(name: str) -> str:
    """
    Create a safe filename string by replacing spaces with underscores
    and removing characters not permitted in Windows/Linux filesystems.
    """
    cleaned = name.strip().replace(" ", "_")
    cleaned = re.sub(r'[\\/*?:"<>|]', "", cleaned)
    cleaned = re.sub(r"_+", "_", cleaned)
    return cleaned.strip("._")


def clean_text(text: str) -> str:
    """
    Clean text description:
    - Decode HTML entities
    - Strip unnecessary HTML tags
    - Preserve meaning and strip surrounding whitespace
    """
    if not text:
        return "Not specified in MITRE ATT&CK data."
    cleaned = html.unescape(text)
    cleaned = re.sub(r"<[^>]+>", "", cleaned)
    cleaned = cleaned.strip()
    return cleaned if cleaned else "Not specified in MITRE ATT&CK data."


def format_field(value) -> str:
    """
    Format metadata fields (strings, lists) into clean text.
    Returns 'Not specified in MITRE ATT&CK data.' if empty or None.
    """
    if value is None:
        return "Not specified in MITRE ATT&CK data."
    if isinstance(value, list):
        items = [str(v).strip() for v in value if str(v).strip()]
        if not items:
            return "Not specified in MITRE ATT&CK data."
        return ", ".join(items)
    val_str = str(value).strip()
    if not val_str:
        return "Not specified in MITRE ATT&CK data."
    return val_str


def process_mitre_attack(
    input_file: str = DEFAULT_INPUT_PATH,
    output_dir: str = DEFAULT_OUTPUT_DIR
):
    """
    Process MITRE ATT&CK STIX JSON into structured text files for RAG.
    """
    resolved_input = resolve_input_path(input_file)

    if not os.path.exists(resolved_input):
        print(
            f"Error: MITRE ATT&CK input file not found at '{input_file}' "
            f"(resolved: '{resolved_input}').",
            file=sys.stderr
        )
        return False

    try:
        with open(resolved_input, "r", encoding="utf-8") as f:
            stix_bundle = json.load(f)
    except json.JSONDecodeError as e:
        print(f"Error: Failed to parse JSON in '{resolved_input}': {e}", file=sys.stderr)
        return False
    except Exception as e:
        print(f"Error reading file '{resolved_input}': {e}", file=sys.stderr)
        return False

    if not isinstance(stix_bundle, dict):
        print("Error: Expected top-level STIX bundle to be a JSON object (dict).", file=sys.stderr)
        return False

    objects = stix_bundle.get("objects", [])
    if not isinstance(objects, list):
        print("Error: Expected 'objects' array in STIX JSON.", file=sys.stderr)
        return False

    # Automatically create output directory
    os.makedirs(output_dir, exist_ok=True)

    total_stix_objects = len(objects)
    attack_patterns_found = 0
    valid_techniques_processed = 0
    files_created = 0
    first_five_techniques = []

    for obj in objects:
        if not isinstance(obj, dict):
            continue

        if obj.get("type") != "attack-pattern":
            continue

        attack_patterns_found += 1

        # Skip revoked or deprecated attack patterns
        if obj.get("revoked") is True or obj.get("x_mitre_deprecated") is True:
            continue

        # Extract MITRE ATT&CK external_id from external_references
        ext_refs = obj.get("external_references", [])
        attack_id = None
        for ref in ext_refs:
            if isinstance(ref, dict) and ref.get("source_name") == "mitre-attack":
                attack_id = ref.get("external_id")
                break

        # If technique has no external ID, skip it
        if not attack_id:
            continue

        technique_name = obj.get("name", "Unnamed Technique").strip()
        description = clean_text(obj.get("description", ""))

        # Tactics from kill_chain_phases
        kill_chain_phases = obj.get("kill_chain_phases", [])
        tactics = []
        for phase in kill_chain_phases:
            if isinstance(phase, dict) and phase.get("phase_name"):
                tactics.append(phase.get("phase_name"))

        # Platforms
        platforms = obj.get("x_mitre_platforms")

        # Detection
        detection_raw = obj.get("x_mitre_detection")
        detection = clean_text(detection_raw) if detection_raw else "Not specified in MITRE ATT&CK data."

        # Permissions Required
        permissions = obj.get("x_mitre_permissions_required")

        # Data Sources
        data_sources = obj.get("x_mitre_data_sources")

        # Construct structured document
        document_content = (
            "MITRE ATT&CK TECHNIQUE\n\n"
            f"Technique ID: {attack_id}\n\n"
            f"Technique Name: {technique_name}\n\n"
            "Description:\n"
            f"{description}\n\n"
            "Tactics:\n"
            f"{format_field(tactics)}\n\n"
            "Platforms:\n"
            f"{format_field(platforms)}\n\n"
            "Detection:\n"
            f"{detection}\n\n"
            "Permissions Required:\n"
            f"{format_field(permissions)}\n\n"
            "Data Sources:\n"
            f"{format_field(data_sources)}\n"
        )

        safe_name = sanitize_filename(technique_name)
        file_name = f"{attack_id}_{safe_name}.txt"
        file_path = os.path.join(output_dir, file_name)

        try:
            with open(file_path, "w", encoding="utf-8") as out_f:
                out_f.write(document_content)
            files_created += 1
            valid_techniques_processed += 1
            if len(first_five_techniques) < 5:
                first_five_techniques.append((attack_id, technique_name, file_name))
        except Exception as e:
            print(f"Warning: Failed to write file for {attack_id}: {e}", file=sys.stderr)

    # Print summary
    print("\nMITRE ATT&CK PROCESSING")
    print("========================")
    print(f"Total STIX objects: {total_stix_objects}")
    print(f"Attack-pattern objects found: {attack_patterns_found}")
    print(f"Valid techniques processed: {valid_techniques_processed}")
    print(f"Files created: {files_created}")

    print("\nFirst 5 Techniques Processed:")
    print("-----------------------------")
    for i, (tid, tname, fname) in enumerate(first_five_techniques, start=1):
        print(f"{i}. [{tid}] {tname} -> {fname}")
    print("========================\n")

    return True


def main():
    process_mitre_attack()


if __name__ == "__main__":
    main()
