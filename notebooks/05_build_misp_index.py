import pandas as pd
import sqlite3
from pathlib import Path

# ---------------------------------------------------------
# Paths
# ---------------------------------------------------------
misp_dir = Path("data/external/misp")
output_db = Path("data/processed/misp_index.db")

output_db.parent.mkdir(parents=True, exist_ok=True)

# ---------------------------------------------------------
# Create SQLite database
# ---------------------------------------------------------
conn = sqlite3.connect(output_db)

print("=" * 60)
print("BUILDING MISP THREAT INTELLIGENCE INDEX")
print("=" * 60)

# ---------------------------------------------------------
# 1. ThreatFox
# ---------------------------------------------------------
print("\n[1/3] Loading ThreatFox...")

tf = pd.read_csv(
    misp_dir / "threatfox_clean.csv",
    dtype=str
)

tf["ioc_value"] = tf["ioc_value"].astype(str).str.strip().str.lower()

tf_index = pd.DataFrame({
    "ioc_value": tf["ioc_value"],
    "ioc_type": tf["ioc_type"],
    "source": "ThreatFox",
    "threat_type": tf["threat_type"],
    "malware": tf["malware_printable"],
    "confidence": tf["confidence_level"],
    "tags": tf["tags"],
    "reference": tf["reference"]
})

tf_index.to_sql(
    "threat_intelligence",
    conn,
    if_exists="append",
    index=False
)

print(f"ThreatFox records indexed: {len(tf_index):,}")

# ---------------------------------------------------------
# 2. URLhaus
# ---------------------------------------------------------
print("\n[2/3] Loading URLhaus...")

uh = pd.read_csv(
    misp_dir / "urlhaus_clean.csv",
    dtype=str
)

uh["url"] = uh["url"].astype(str).str.strip().str.lower()

uh_index = pd.DataFrame({
    "ioc_value": uh["url"],
    "ioc_type": "url",
    "source": "URLhaus",
    "threat_type": uh["threat"],
    "malware": "",
    "confidence": "",
    "tags": uh["tags"],
    "reference": uh["urlhaus_link"]
})

uh_index.to_sql(
    "threat_intelligence",
    conn,
    if_exists="append",
    index=False
)

print(f"URLhaus records indexed: {len(uh_index):,}")

# ---------------------------------------------------------
# 3. MalwareBazaar
# ---------------------------------------------------------
print("\n[3/3] Loading MalwareBazaar...")

mb = pd.read_csv(
    misp_dir / "malwarebazaar_clean.csv",
    dtype=str
)

mb["md5_hash"] = (
    mb["md5_hash"]
    .astype(str)
    .str.strip()
    .str.lower()
)

mb_index = pd.DataFrame({
    "ioc_value": mb["md5_hash"],
    "ioc_type": "md5_hash",
    "source": "MalwareBazaar",
    "threat_type": "malware_sample",
    "malware": "",
    "confidence": "",
    "tags": "",
    "reference": ""
})

mb_index.to_sql(
    "threat_intelligence",
    conn,
    if_exists="append",
    index=False
)

print(f"MalwareBazaar records indexed: {len(mb_index):,}")

# ---------------------------------------------------------
# Create fast lookup index
# ---------------------------------------------------------
print("\nCreating database indexes...")

conn.execute("""
    CREATE INDEX IF NOT EXISTS idx_ioc_value
    ON threat_intelligence(ioc_value)
""")

conn.execute("""
    CREATE INDEX IF NOT EXISTS idx_ioc_type
    ON threat_intelligence(ioc_type)
""")

conn.execute("""
    CREATE INDEX IF NOT EXISTS idx_source
    ON threat_intelligence(source)
""")

conn.commit()

# ---------------------------------------------------------
# Verification
# ---------------------------------------------------------
total = conn.execute(
    "SELECT COUNT(*) FROM threat_intelligence"
).fetchone()[0]

sources = conn.execute("""
    SELECT source, COUNT(*)
    FROM threat_intelligence
    GROUP BY source
""").fetchall()

conn.close()

print("\n" + "=" * 60)
print("SUCCESS")
print("=" * 60)

print(f"Total indexed records: {total:,}")

print("\nRecords by source:")
for source, count in sources:
    print(f"{source}: {count:,}")

print(f"\nDatabase:")
print(output_db)