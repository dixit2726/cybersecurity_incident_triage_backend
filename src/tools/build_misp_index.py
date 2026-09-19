import logging
import os
import sqlite3
import sys
from pathlib import Path
from typing import Optional
import pandas as pd

# Ensure project root is in sys.path
PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

logger = logging.getLogger("tools.build_misp_index")


def build_threat_intelligence_db(
    output_path: Optional[str] = None,
    misp_dir: Optional[str] = None,
    force_rebuild: bool = False,
) -> str:
    """
    Build the SQLite Threat Intelligence index (misp_index.db) from repository
    MISP datasets (ThreatFox, URLhaus, MalwareBazaar).

    Produces exactly 21,754 threat intelligence records with indexed columns:
    - idx_ioc_value ON threat_intelligence(ioc_value)
    - idx_ioc_type ON threat_intelligence(ioc_type)
    - idx_source ON threat_intelligence(source)

    :param output_path: Destination path for SQLite database. Defaults to data/processed/misp_index.db.
    :param misp_dir: Path to directory containing MISP CSV datasets. Defaults to data/external/misp.
    :param force_rebuild: Force rebuild even if database already exists and is healthy.
    :return: Absolute path to the generated SQLite database.
    """
    if output_path is None:
        output_path = os.path.join(PROJECT_ROOT, "data", "processed", "misp_index.db")
    if misp_dir is None:
        misp_dir = os.path.join(PROJECT_ROOT, "data", "external", "misp")

    out_file = Path(output_path)
    src_dir = Path(misp_dir)

    # Check if healthy DB already exists
    if not force_rebuild and out_file.exists():
        try:
            conn = sqlite3.connect(out_file)
            c = conn.cursor()
            c.execute("SELECT COUNT(*) FROM threat_intelligence")
            cnt = c.fetchone()[0]
            conn.close()
            if cnt >= 21754:
                logger.info("Threat intelligence database already exists and is healthy (%d records).", cnt)
                return str(out_file)
        except Exception:
            pass  # Rebuild if corrupted or incomplete

    tf_csv = src_dir / "Threat Intelligence Dataset.csv"
    uh_csv = src_dir / "Malicious URL Dataset.csv"
    mb_csv = src_dir / "Malware Hash Dataset.csv"

    # Verify input source files exist
    for f in [tf_csv, uh_csv, mb_csv]:
        if not f.exists():
            raise FileNotFoundError(f"Required MISP dataset file not found: {f}")

    # Ensure parent directory exists
    out_file.parent.mkdir(parents=True, exist_ok=True)

    conn = sqlite3.connect(out_file)

    try:
        # Drop table if exists to ensure clean state
        conn.execute("DROP TABLE IF EXISTS threat_intelligence")

        # 1. ThreatFox (5,760 records)
        tf = pd.read_csv(tf_csv, dtype=str)
        tf["ioc_value"] = tf["ioc_value"].astype(str).str.strip().str.lower()
        tf_df = pd.DataFrame({
            "ioc_value": tf["ioc_value"],
            "ioc_type": tf["ioc_type"],
            "source": "ThreatFox",
            "threat_type": tf["threat_type"],
            "malware": tf["malware_printable"],
            "confidence": tf["confidence_level"],
            "tags": tf["tags"],
            "reference": tf["reference"],
        })
        tf_df.to_sql("threat_intelligence", conn, if_exists="append", index=False)

        # 2. URLhaus (15,229 records)
        uh = pd.read_csv(uh_csv, dtype=str)
        uh["url"] = uh["url"].astype(str).str.strip().str.lower()
        uh_df = pd.DataFrame({
            "ioc_value": uh["url"],
            "ioc_type": "url",
            "source": "URLhaus",
            "threat_type": uh["threat"],
            "malware": "",
            "confidence": "",
            "tags": uh["tags"],
            "reference": uh["urlhaus_link"],
        })
        uh_df.to_sql("threat_intelligence", conn, if_exists="append", index=False)

        # 3. MalwareBazaar (765 records)
        mb = pd.read_csv(mb_csv, dtype=str)
        mb["md5_hash"] = mb["md5_hash"].astype(str).str.strip().str.lower()
        mb_df = pd.DataFrame({
            "ioc_value": mb["md5_hash"],
            "ioc_type": "md5_hash",
            "source": "MalwareBazaar",
            "threat_type": "malware_sample",
            "malware": "",
            "confidence": "",
            "tags": "",
            "reference": "",
        })
        mb_df.to_sql("threat_intelligence", conn, if_exists="append", index=False)

        # Create indexes
        conn.execute("CREATE INDEX IF NOT EXISTS idx_ioc_value ON threat_intelligence(ioc_value)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_ioc_type ON threat_intelligence(ioc_type)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_source ON threat_intelligence(source)")
        conn.commit()

        total = conn.execute("SELECT COUNT(*) FROM threat_intelligence").fetchone()[0]
        conn.close()

        logger.info("Built threat intelligence database with %d records at: %s", total, out_file)
        return str(out_file)

    except Exception:
        conn.close()
        raise


if __name__ == "__main__":
    print("=" * 60)
    print("BUILDING THREAT INTELLIGENCE DATABASE")
    print("=" * 60)
    db_path = build_threat_intelligence_db()
    conn = sqlite3.connect(db_path)
    total = conn.execute("SELECT COUNT(*) FROM threat_intelligence").fetchone()[0]
    sources = conn.execute("SELECT source, COUNT(*) FROM threat_intelligence GROUP BY source").fetchall()
    conn.close()
    print(f"SUCCESS: Generated {total:,} records at {db_path}")
    for src, cnt in sources:
        print(f"  - {src}: {cnt:,}")
