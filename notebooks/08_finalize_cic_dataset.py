import pandas as pd
import numpy as np
from pathlib import Path

input_file = Path("data/processed/cic_ids2017_features.csv")
output_file = Path("data/processed/cic_ids2017_final.csv")

print("=" * 60)
print("FINALIZING CIC-IDS2017 DATASET")
print("=" * 60)

# Load feature-selected dataset
df = pd.read_csv(input_file)

print(f"\nOriginal rows: {len(df):,}")
print(f"Original columns: {len(df.columns)}")

# ---------------------------------------------------------
# 1. Detect infinite values
# ---------------------------------------------------------
numeric_columns = df.select_dtypes(include=np.number).columns

infinite_counts = np.isinf(df[numeric_columns]).sum()

print("\nInfinite values found:")
print(infinite_counts[infinite_counts > 0].to_string())

# ---------------------------------------------------------
# 2. Replace infinity with NaN
# ---------------------------------------------------------
df[numeric_columns] = df[numeric_columns].replace(
    [np.inf, -np.inf],
    np.nan
)

# ---------------------------------------------------------
# 3. Replace resulting NaN values with column median
# ---------------------------------------------------------
for column in numeric_columns:
    if df[column].isna().any():
        median_value = df[column].median()
        df[column] = df[column].fillna(median_value)

        print(
            f"Fixed {column}: "
            f"replaced invalid values with median "
            f"{median_value}"
        )

# ---------------------------------------------------------
# 4. Check final data quality
# ---------------------------------------------------------
missing_values = df.isna().sum().sum()
infinite_values = np.isinf(
    df[numeric_columns].to_numpy()
).sum()

duplicates = df.duplicated().sum()

# ---------------------------------------------------------
# 5. Save NEW final dataset
# ---------------------------------------------------------
df.to_csv(output_file, index=False)

print("\n" + "=" * 60)
print("FINAL DATASET VALIDATION")
print("=" * 60)

print(f"Rows:              {len(df):,}")
print(f"Columns:           {len(df.columns)}")
print(f"Missing values:    {missing_values:,}")
print(f"Infinite values:   {infinite_values:,}")
print(f"Feature duplicates:{duplicates:,}")

print("\nOutput:")
print(output_file)

print("\n" + "=" * 60)

if (
    missing_values == 0
    and infinite_values == 0
    and len(df.columns) == 25
):
    print("CIC FINAL DATASET READY")
else:
    print("VALIDATION FAILED")

print("=" * 60)