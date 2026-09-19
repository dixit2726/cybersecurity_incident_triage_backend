import pandas as pd
import numpy as np
from pathlib import Path

input_file = Path("data/processed/cic_ids2017_features.csv")

print("=" * 60)
print("CIC-IDS2017 DATA VALIDATION")
print("=" * 60)

# Read the feature dataset
df = pd.read_csv(input_file)

print(f"\nRows: {len(df):,}")
print(f"Columns: {len(df.columns)}")

# 1. Duplicate check
duplicates = df.duplicated().sum()
print(f"\nDuplicate rows: {duplicates:,}")

# 2. Missing-value check
missing_total = df.isna().sum().sum()
print(f"Missing values: {missing_total:,}")

# 3. Infinite-value check
numeric_df = df.select_dtypes(include=np.number)
infinite_values = np.isinf(numeric_df.to_numpy()).sum()
print(f"Infinite values: {infinite_values:,}")

# 4. Label check
print("\nAttack labels:")
print(df["Label"].value_counts().to_string())

# 5. Required columns
required_columns = [
    "Destination Port",
    "Flow Duration",
    "Total Fwd Packets",
    "Total Backward Packets",
    "Flow Bytes/s",
    "Flow Packets/s",
    "SYN Flag Count",
    "RST Flag Count",
    "ACK Flag Count",
    "Label"
]

missing_columns = [
    c for c in required_columns
    if c not in df.columns
]

print("\nMissing required columns:")
print(missing_columns if missing_columns else "None")

# 6. Numeric feature validation
non_numeric = []

for column in df.columns:
    if column != "Label":
        converted = pd.to_numeric(df[column], errors="coerce")

        if converted.isna().any():
            non_numeric.append(column)

print("\nFeatures containing non-numeric values:")
print(non_numeric if non_numeric else "None")

# 7. Expected size
expected_rows = 2_522_009
expected_columns = 25

print("\nExpected rows:", f"{expected_rows:,}")
print("Expected columns:", expected_columns)

# 8. Overall validation
validation_passed = (
    len(df) == expected_rows
    and len(df.columns) == expected_columns
    and duplicates == 0
    and missing_total == 0
    and infinite_values == 0
    and len(missing_columns) == 0
    and len(non_numeric) == 0
    and "Label" in df.columns
)

print("\n" + "=" * 60)

if validation_passed:
    print("VALIDATION PASSED")
else:
    print("VALIDATION FAILED")

print("=" * 60)