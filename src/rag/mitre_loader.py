import json
import os
import sys


DEFAULT_MITRE_PATH = os.path.join(
    "data",
    "rag",
    "mitre",
    "enterprise-attack.json"
)


def resolve_file_path(file_path: str = DEFAULT_MITRE_PATH) -> str:
    """
    Resolve file path relative to current working directory or project root.
    """
    if os.path.exists(file_path):
        return file_path

    # Check relative to this script's directory
    alt_path = os.path.abspath(
        os.path.join(
            os.path.dirname(__file__),
            "..",
            "..",
            file_path
        )
    )
    if os.path.exists(alt_path):
        return alt_path

    return file_path


def load_mitre_attack(file_path: str = DEFAULT_MITRE_PATH):
    """
    Load the MITRE Enterprise ATT&CK STIX JSON file using Python's json module.
    Returns the parsed data dictionary or None on error.
    """
    resolved_path = resolve_file_path(file_path)

    if not os.path.exists(resolved_path):
        print(f"Error: MITRE ATT&CK file not found at '{file_path}' (resolved: '{resolved_path}').", file=sys.stderr)
        return None

    try:
        with open(resolved_path, "r", encoding="utf-8") as f:
            data = json.load(f)
        return data
    except json.JSONDecodeError as e:
        print(f"Error: Failed to parse JSON file at '{resolved_path}': {e}", file=sys.stderr)
        return None
    except Exception as e:
        print(f"Error reading MITRE ATT&CK file at '{resolved_path}': {e}", file=sys.stderr)
        return None


def inspect_mitre_objects(data, preview_count: int = 5):
    """
    Inspect the STIX objects array, count total objects and attack-patterns,
    and display the first preview_count attack-pattern objects.
    """
    if not isinstance(data, dict):
        print("Error: Expected top-level STIX bundle to be a JSON object (dict).", file=sys.stderr)
        return

    objects = data.get("objects", [])
    if not isinstance(objects, list):
        print("Error: Expected 'objects' key to be a list in the STIX bundle.", file=sys.stderr)
        return

    total_objects = len(objects)
    attack_patterns = [
        obj for obj in objects
        if isinstance(obj, dict) and obj.get("type") == "attack-pattern"
    ]
    total_attack_patterns = len(attack_patterns)

    print("=" * 60)
    print("MITRE ATT&CK STIX DATASET INSPECTION")
    print("=" * 60)
    print(f"Total STIX objects          : {total_objects}")
    print(f"Total attack-pattern objects: {total_attack_patterns}")
    print("=" * 60)

    print(f"\nFIRST {min(preview_count, total_attack_patterns)} ATTACK-PATTERN OBJECTS:\n")

    for i, pattern in enumerate(attack_patterns[:preview_count], start=1):
        obj_id = pattern.get("id", "N/A")
        obj_name = pattern.get("name", "N/A")
        raw_desc = pattern.get("description", "No description available.")
        # Truncate to first 300 characters
        obj_desc = raw_desc[:300]

        print(f"[{i}] ID: {obj_id}")
        print(f"    Name: {obj_name}")
        print(f"    Description (first 300 chars):")
        print(f"    {obj_desc}")
        print("-" * 60)


def main():
    data = load_mitre_attack()
    if data is not None:
        inspect_mitre_objects(data, preview_count=5)


if __name__ == "__main__":
    main()
