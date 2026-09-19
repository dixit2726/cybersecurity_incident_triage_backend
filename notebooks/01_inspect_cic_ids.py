import pandas as pd
from pathlib import Path

# Folder containing the original CIC-IDS2017 CSV files
RAW_DIR = Path("data/raw")

# Find all CSV files
csv_files = list(RAW_DIR.glob("*.csv"))

print(f"Found {len(csv_files)} CSV files\n")

# Read and combine
dataframes = []

for file in csv_files:
    print(f"Reading: {file.name}")

    df = pd.read_csv(file, low_memory=False)

    # Remove accidental spaces from column names
    df.columns = df.columns.str.strip()

    dataframes.append(df)

# Combine all files
master_df = pd.concat(dataframes, ignore_index=True)

print("\n" + "=" * 60)
print("MASTER DATASET INFORMATION")
print("=" * 60)

print(f"Total records: {len(master_df):,}")
print(f"Total columns: {len(master_df.columns)}")

print("\nColumns:")
for column in master_df.columns:
    print("-", column)

# Find Label column
label_column = next(
    (col for col in master_df.columns if col.lower() == "label"),
    None
)

if label_column:
    print("\n" + "=" * 60)
    print("LABEL DISTRIBUTION")
    print("=" * 60)

    print(master_df[label_column].value_counts(dropna=False))

else:
    print("\nWARNING: Label column was not found!")

# Missing values
print("\n" + "=" * 60)
print("MISSING VALUES")
print("=" * 60)

missing = master_df.isna().sum()
print(missing[missing > 0].sort_values(ascending=False).head(20))

# Duplicate rows
print("\n" + "=" * 60)
print("DUPLICATES")
print("=" * 60)

print(f"Duplicate rows: {master_df.duplicated().sum():,}")

# Save master dataset
output_file = Path("data/processed/master_cic_ids2017.csv")
output_file.parent.mkdir(parents=True, exist_ok=True)

master_df.to_csv(output_file, index=False)

print("\n" + "=" * 60)
print(f"Saved master dataset to: {output_file}")
print("=" * 60)