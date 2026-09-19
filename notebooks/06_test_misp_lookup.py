import sqlite3
from pathlib import Path

db_file = Path("data/processed/misp_index.db")

print("=" * 60)
print("MISP LOOKUP TEST")
print("=" * 60)

conn = sqlite3.connect(db_file)

# Get one real IOC from the database
row = conn.execute("""
    SELECT ioc_value
    FROM threat_intelligence
    WHERE ioc_value IS NOT NULL
    AND ioc_value != ''
    LIMIT 1
""").fetchone()

if row is None:
    print("ERROR: No IOC found in database.")
    conn.close()
    raise SystemExit

test_ioc = row[0]

print(f"\nTesting IOC:")
print(test_ioc)

# Search for that IOC
results = conn.execute("""
    SELECT
        ioc_value,
        ioc_type,
        source,
        threat_type,
        malware,
        confidence,
        tags
    FROM threat_intelligence
    WHERE ioc_value = ?
""", (test_ioc,)).fetchall()

print(f"\nMatches found: {len(results)}")

for result in results:
    print("\nMatch:")
    print(f"IOC:        {result[0]}")
    print(f"Type:       {result[1]}")
    print(f"Source:     {result[2]}")
    print(f"Threat:     {result[3]}")
    print(f"Malware:    {result[4]}")
    print(f"Confidence: {result[5]}")
    print(f"Tags:       {result[6]}")

conn.close()

print("\n" + "=" * 60)
print("LOOKUP TEST PASSED")
print("=" * 60)
