import pandas as pd
from pathlib import Path

# Input and output paths
input_file = Path("data/processed/cic_ids2017_clean.csv")
output_file = Path("data/processed/cic_ids2017_features.csv")

# Features selected for Cybersecurity Incident Triage AI
selected_features = [
    "Destination Port",
    "Flow Duration",
    "Total Fwd Packets",
    "Total Backward Packets",
    "Total Length of Fwd Packets",
    "Total Length of Bwd Packets",
    "Fwd Packet Length Max",
    "Fwd Packet Length Mean",
    "Bwd Packet Length Max",
    "Bwd Packet Length Mean",
    "Flow Bytes/s",
    "Flow Packets/s",
    "Flow IAT Mean",
    "Flow IAT Std",
    "Fwd IAT Mean",
    "Bwd IAT Mean",
    "FIN Flag Count",
    "SYN Flag Count",
    "RST Flag Count",
    "PSH Flag Count",
    "ACK Flag Count",
    "Average Packet Size",
    "Init_Win_bytes_forward",
    "Init_Win_bytes_backward",
    "Label"
]

print("=" * 60)
print("CIC-IDS2017 FEATURE SELECTION")
print("=" * 60)

# Process in chunks to avoid memory problems
first_chunk = True
total_rows = 0

for chunk in pd.read_csv(input_file, chunksize=100_000):
    selected = chunk[selected_features]

    if first_chunk:
        selected.to_csv(output_file, index=False)
        first_chunk = False
    else:
        selected.to_csv(
            output_file,
            mode="a",
            header=False,
            index=False
        )

    total_rows += len(selected)
    print(f"Processed: {total_rows:,} rows")

print("\n" + "=" * 60)
print("SUCCESS")
print("=" * 60)
print(f"Rows: {total_rows:,}")
print(f"Features: {len(selected_features)}")
print(f"Output: {output_file}")