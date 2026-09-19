import pandas as pd
from pathlib import Path

INPUT_FILE = Path("data/processed/master_cic_ids2017.csv")
OUTPUT_FILE = Path("data/processed/cic_ids2017_clean.csv")

CHUNK_SIZE = 100_000

print("=" * 60)
print("CIC-IDS2017 MEMORY-EFFICIENT CLEANING")
print("=" * 60)

print(f"Input : {INPUT_FILE}")
print(f"Output: {OUTPUT_FILE}")
print(f"Chunk size: {CHUNK_SIZE:,}")

# Remove old output if it exists
if OUTPUT_FILE.exists():
    OUTPUT_FILE.unlink()

seen_hashes = set()
total_input = 0
total_output = 0
total_missing_removed = 0
total_duplicates_removed = 0

first_chunk = True

# Read the large CSV in chunks
for chunk_number, df in enumerate(
    pd.read_csv(
        INPUT_FILE,
        chunksize=CHUNK_SIZE,
        low_memory=False
    ),
    start=1
):

    print(f"\nProcessing chunk {chunk_number}...")

    total_input += len(df)

    # ---------------------------------------------------------
    # 1. Clean column names
    # ---------------------------------------------------------
    df.columns = df.columns.str.strip()

    # ---------------------------------------------------------
    # 2. Clean Label column
    # ---------------------------------------------------------
    label_col = next(
        (col for col in df.columns if col.lower() == "label"),
        None
    )

    if label_col is None:
        raise ValueError("Label column not found.")

    df[label_col] = (
        df[label_col]
        .astype(str)
        .str.strip()
    )

    # Fix encoding problems seen in your dataset
    df[label_col] = df[label_col].str.replace(
        "�",
        "-",
        regex=False
    )

    # Standardize SQL Injection capitalization
    df[label_col] = df[label_col].str.replace(
        "Web Attack - Sql Injection",
        "Web Attack - SQL Injection",
        regex=False
    )

    # ---------------------------------------------------------
    # 3. Remove rows with missing Flow Bytes/s
    # ---------------------------------------------------------
    if "Flow Bytes/s" in df.columns:

        missing_count = df["Flow Bytes/s"].isna().sum()

        if missing_count > 0:
            print(
                f"  Removing missing Flow Bytes/s: "
                f"{missing_count:,}"
            )

            df = df.dropna(
                subset=["Flow Bytes/s"]
            )

            total_missing_removed += missing_count

    # ---------------------------------------------------------
    # 4. Remove exact duplicate rows
    # ---------------------------------------------------------
    if len(df) > 0:

        row_hashes = pd.util.hash_pandas_object(
            df,
            index=False
        )

        keep_mask = []

        for h in row_hashes:
            h = int(h)

            if h in seen_hashes:
                keep_mask.append(False)
            else:
                seen_hashes.add(h)
                keep_mask.append(True)

        before_duplicates = len(df)

        df = df.loc[keep_mask]

        duplicates_removed = (
            before_duplicates - len(df)
        )

        total_duplicates_removed += duplicates_removed

        if duplicates_removed > 0:
            print(
                f"  Duplicate rows removed: "
                f"{duplicates_removed:,}"
            )

    # ---------------------------------------------------------
    # 5. Write cleaned chunk
    # ---------------------------------------------------------
    if len(df) > 0:

        df.to_csv(
            OUTPUT_FILE,
            mode="w" if first_chunk else "a",
            header=first_chunk,
            index=False
        )

        first_chunk = False
        total_output += len(df)

    print(f"  Rows kept: {len(df):,}")

# -------------------------------------------------------------
# Final report
# -------------------------------------------------------------

print("\n" + "=" * 60)
print("CLEANING COMPLETE")
print("=" * 60)

print(f"Original rows:          {total_input:,}")
print(f"Missing rows removed:   {total_missing_removed:,}")
print(f"Duplicate rows removed: {total_duplicates_removed:,}")
print(f"Final rows:             {total_output:,}")

print("\nOutput file:")
print(OUTPUT_FILE)

# -------------------------------------------------------------
# Verify final file
# -------------------------------------------------------------

print("\nVerifying output...")

final_df = pd.read_csv(
    OUTPUT_FILE,
    nrows=5,
    low_memory=False
)

print(f"Final columns: {len(final_df.columns)}")

print("\nFinal columns:")
for column in final_df.columns:
    print("-", column)

print("\n" + "=" * 60)
print("SUCCESS")
print("=" * 60)