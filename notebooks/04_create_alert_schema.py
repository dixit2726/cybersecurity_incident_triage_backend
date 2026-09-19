import pandas as pd
from pathlib import Path

# Input and output
input_file = Path("data/processed/cic_ids2017_features.csv")
output_file = Path("data/processed/alert_schema_sample.csv")

# Read only a small sample first
df = pd.read_csv(input_file, nrows=1000)

# ---------------------------------------------------------
# Map CIC labels to broader attack families
# ---------------------------------------------------------
def get_attack_family(label):
    label = str(label).strip()

    if label == "BENIGN":
        return "Benign"

    if label == "DDoS":
        return "DDoS"

    if label.startswith("DoS"):
        return "DoS"

    if label == "PortScan":
        return "Reconnaissance"

    if label in [
        "FTP-Patator",
        "SSH-Patator",
        "Web Attack - Brute Force"
    ]:
        return "Brute Force"

    if label in [
        "Web Attack - XSS",
        "Web Attack - SQL Injection"
    ]:
        return "Web Attack"

    if label == "Bot":
        return "Bot"

    if label == "Infiltration":
        return "Infiltration"

    if label == "Heartbleed":
        return "Exploitation"

    return "Other"


# Create alert IDs
df.insert(
    0,
    "alert_id",
    ["CIC-" + str(i).zfill(6) for i in range(1, len(df) + 1)]
)

# Create attack family
df["attack_family"] = df["Label"].apply(get_attack_family)

# ---------------------------------------------------------
# Fields reserved for later MISP / MITRE / Triage Engine
# ---------------------------------------------------------
df["ioc_value"] = ""
df["ioc_type"] = ""
df["threat_type"] = ""
df["malware"] = ""
df["misp_confidence"] = ""
df["threat_intelligence_match"] = False

df["mitre_tactic"] = ""
df["mitre_technique"] = ""

df["priority"] = ""
df["recommended_action"] = ""
df["explanation"] = ""

# Rename Label to clearer project terminology
df = df.rename(columns={"Label": "attack_label"})

# Save sample
df.to_csv(output_file, index=False)

# ---------------------------------------------------------
# Verification
# ---------------------------------------------------------
print("=" * 60)
print("PROJECT-READY ALERT SCHEMA")
print("=" * 60)

print(f"Sample rows: {len(df):,}")
print(f"Total columns: {len(df.columns)}")
print(f"Output: {output_file}")

print("\nAttack families:")
print(df["attack_family"].value_counts().to_string())

print("\nColumns:")
for i, column in enumerate(df.columns, 1):
    print(f"{i}. {column}")

print("\n" + "=" * 60)
print("SUCCESS")
print("=" * 60)