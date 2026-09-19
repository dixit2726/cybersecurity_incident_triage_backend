import pandas as pd
import re
from pathlib import Path

MISP_DIR = Path("data/external/misp")

files = {
    "ThreatFox": "threatfox_clean.csv",
    "URLhaus": "urlhaus_clean.csv",
    "MalwareBazaar": "malwarebazaar_clean.csv",
}

print("=" * 60)
print("MISP DATA VALIDATION")
print("=" * 60)

all_passed = True

# ---------------------------------------------------------
# ThreatFox
# ---------------------------------------------------------
print("\n[1/3] ThreatFox")

tf = pd.read_csv(MISP_DIR / files["ThreatFox"], dtype=str)

print(f"Rows: {len(tf):,}")
print(f"Columns: {len(tf.columns)}")

tf_ioc = tf["ioc_value"].fillna("").str.strip()

tf_empty = (tf_ioc == "").sum()
tf_duplicates = tf_ioc.duplicated().sum()

print(f"Empty IOC values: {tf_empty:,}")
print(f"Duplicate IOC values: {tf_duplicates:,}")

print("\nIOC types:")
print(tf["ioc_type"].value_counts().to_string())

if tf_empty > 0:
    all_passed = False


# ---------------------------------------------------------
# URLhaus
# ---------------------------------------------------------
print("\n[2/3] URLhaus")

uh = pd.read_csv(MISP_DIR / files["URLhaus"], dtype=str)

print(f"Rows: {len(uh):,}")
print(f"Columns: {len(uh.columns)}")

urls = uh["url"].fillna("").str.strip()

empty_urls = (urls == "").sum()
duplicate_urls = urls.duplicated().sum()

print(f"Empty URLs: {empty_urls:,}")
print(f"Duplicate URLs: {duplicate_urls:,}")

print("\nURL status:")
print(uh["url_status"].value_counts().to_string())

if empty_urls > 0:
    all_passed = False


# ---------------------------------------------------------
# MalwareBazaar
# ---------------------------------------------------------
print("\n[3/3] MalwareBazaar")

mb = pd.read_csv(MISP_DIR / files["MalwareBazaar"], dtype=str)

print(f"Rows: {len(mb):,}")
print(f"Columns: {len(mb.columns)}")

hashes = (
    mb["md5_hash"]
    .fillna("")
    .str.strip()
    .str.lower()
)

empty_hashes = (hashes == "").sum()
duplicate_hashes = hashes.duplicated().sum()

invalid_hashes = (
    ~hashes.str.match(r"^[a-f0-9]{32}$")
    & (hashes != "")
).sum()

print(f"Empty MD5 hashes: {empty_hashes:,}")
print(f"Duplicate MD5 hashes: {duplicate_hashes:,}")
print(f"Invalid MD5 hashes: {invalid_hashes:,}")

if empty_hashes > 0 or invalid_hashes > 0:
    all_passed = False


# ---------------------------------------------------------
# Final summary
# ---------------------------------------------------------
print("\n" + "=" * 60)
print("MISP VALIDATION SUMMARY")
print("=" * 60)

print(f"ThreatFox records:     {len(tf):,}")
print(f"URLhaus records:       {len(uh):,}")
print(f"MalwareBazaar records: {len(mb):,}")
print(f"Total records:         {len(tf) + len(uh) + len(mb):,}")

print("\n" + "=" * 60)

if all_passed:
    print("MISP DATA VALIDATION PASSED")
else:
    print("MISP DATA VALIDATION NEEDS REVIEW")

print("=" * 60)