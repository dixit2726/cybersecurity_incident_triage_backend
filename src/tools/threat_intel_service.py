import logging
import os
import re
import sqlite3
import sys
import threading
from typing import Any, Dict, List, Optional

logger = logging.getLogger("tools.threat_intel_service")

# Ensure project root is in sys.path
PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

# Safely handle Windows console encodings (e.g. cp1252)
if hasattr(sys.stdout, "reconfigure"):
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass


from src.tools.abusech_api_client import AbuseCHClient


def deduplicate_matches(matches: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """
    Deduplicate equivalent matches using (source, ioc, threat_type, malware).
    Preserves first encountered order.
    """
    seen = set()
    deduped = []
    for m in matches:
        key = (
            str(m.get("source", "")).strip().lower(),
            str(m.get("ioc", "")).strip().lower(),
            str(m.get("threat_type", "")).strip().lower(),
            str(m.get("malware", "")).strip().lower(),
        )
        if key not in seen:
            seen.add(key)
            deduped.append(m)
    return deduped


class ThreatIntelService:
    """
    Reusable Threat Intelligence Lookup Service.
    Queries the local, offline SQLite database (data/processed/misp_index.db)
    built from ThreatFox, URLhaus, and MalwareBazaar, with optional live Abuse.ch
    enrichment.

    CRITICAL BOUNDARIES:
    - Default behavior: 100% offline; makes no live external API requests unless enable_live=True.
    - Parameterized queries to prevent SQL injection.
    - Preserves exact source-attributed threat records.
    - Enforces private IP filtering before any live external request.
    """

    SUPPORTED_IOC_TYPES = {
        "ip",
        "ipv4",
        "ipv6",
        "ip:port",
        "domain",
        "url",
        "md5",
        "md5_hash",
        "sha1",
        "sha1_hash",
        "sha256",
        "sha256_hash",
        "hash",
    }

    def __init__(
        self,
        db_path: str = "data/processed/misp_index.db",
        enable_live: bool = False,
        live_client: Optional[AbuseCHClient] = None,
    ):
        # Resolve path relative to working directory or project root
        resolved_path = db_path
        if not os.path.isabs(resolved_path):
            if not os.path.exists(resolved_path):
                alt_path = os.path.join(PROJECT_ROOT, db_path)
                if os.path.exists(alt_path):
                    resolved_path = alt_path
                else:
                    # Auto-initialization fallback: build from repository MISP datasets if missing
                    try:
                        from src.tools.build_misp_index import build_threat_intelligence_db
                        logger.info("Threat intelligence database not found at %s. Auto-generating...", alt_path)
                        build_threat_intelligence_db(output_path=alt_path)
                        if os.path.exists(alt_path):
                            resolved_path = alt_path
                    except Exception as exc:
                        logger.warning("Auto-generation of threat intelligence database failed: %s", exc)

        if not os.path.exists(resolved_path):
            raise FileNotFoundError(f"Threat intelligence database not found at: {db_path}")

        self.db_path = os.path.abspath(resolved_path)
        self._local = threading.local()
        self.enable_live = enable_live
        self.live_client = live_client or AbuseCHClient()

    def _get_connection(self) -> sqlite3.Connection:
        """
        Thread-safe SQLite connection manager.
        Allocates and caches a connection per calling thread so that background
        worker threads (such as FastAPI run_in_threadpool) never share connections.
        """
        conn = getattr(self._local, "conn", None)
        if conn is None:
            conn = sqlite3.connect(self.db_path)
            self._local.conn = conn
        return conn

    @property
    def conn(self) -> sqlite3.Connection:
        """Backward-compatible property accessor returning thread-local connection."""
        return self._get_connection()

    def lookup(
        self,
        ioc: str,
        ioc_type: Optional[str] = None,
        enable_live: Optional[bool] = None,
    ) -> List[Dict[str, Any]]:
        """
        Look up a single IOC against the local threat intelligence index, with
        optional live Abuse.ch enrichment.

        :param ioc: The indicator value (IP, domain, URL, hash).
        :param ioc_type: Optional IOC type hint.
        :param enable_live: Optional flag to enable/disable live API lookup for this query.
                            Defaults to self.enable_live (False by default).
        :return: List of structured match dictionaries or [] if no match.
        """
        if not isinstance(ioc, str) or not ioc.strip():
            raise ValueError("IOC cannot be empty.")

        clean_ioc = ioc.strip().lower()

        # Validate IOC type if provided
        norm_type = None
        if ioc_type is not None:
            if not isinstance(ioc_type, str) or not ioc_type.strip():
                raise ValueError("IOC type cannot be empty when specified.")
            norm_type = ioc_type.strip().lower()
            if norm_type not in self.SUPPORTED_IOC_TYPES:
                raise ValueError(f"Unsupported IOC type: '{ioc_type}'")

        cursor = self._get_connection().cursor()

        # Check if the IOC is an IPv4 address (without port)
        is_ipv4 = bool(re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", clean_ioc))

        if is_ipv4 or (norm_type in ["ip", "ipv4"] and ":" not in clean_ioc):
            # Match either exact IP or IP:PORT (e.g. 154.91.59.119:8084) using safe parameterized query
            query = """
                SELECT ioc_value, ioc_type, source, threat_type, malware, confidence, tags, reference
                FROM threat_intelligence
                WHERE ioc_value = ? OR (ioc_value LIKE ? || ':%')
            """
            cursor.execute(query, (clean_ioc, clean_ioc))
        else:
            # Exact parameterized match
            query = """
                SELECT ioc_value, ioc_type, source, threat_type, malware, confidence, tags, reference
                FROM threat_intelligence
                WHERE ioc_value = ?
            """
            cursor.execute(query, (clean_ioc,))

        rows = cursor.fetchall()
        results: List[Dict[str, Any]] = []

        for row in rows:
            results.append({
                "ioc": row[0],
                "ioc_type": row[1],
                "source": row[2],
                "threat_type": row[3],
                "malware": row[4],
                "confidence": row[5],
                "tags": row[6],
                "reference": row[7],
                "source_origin": "local",
            })

        # Check if live lookup should be executed
        should_run_live = self.enable_live if enable_live is None else enable_live

        if should_run_live and self.live_client:
            try:
                live_matches = self.live_client.lookup(ioc.strip(), ioc_type=norm_type)
            except Exception:
                live_matches = []

            if live_matches:
                results = deduplicate_matches(results + live_matches)

        return results

    def lookup_many(
        self,
        iocs: List[Dict[str, str]],
        enable_live: Optional[bool] = None,
    ) -> Dict[str, List[Dict[str, Any]]]:
        """
        Batch lookup for multiple IOC items.

        :param iocs: List of dicts, e.g. [{"type": "ip", "value": "185.220.101.45"}, ...]
        :param enable_live: Optional flag to enable/disable live API lookup.
        :return: Dict mapping original IOC value to its list of match results.
        """
        results: Dict[str, List[Dict[str, Any]]] = {}

        for item in iocs:
            val = item.get("value") or item.get("ioc")
            if not val:
                continue
            ioc_type = item.get("type") or item.get("ioc_type")
            try:
                results[val] = self.lookup(val, ioc_type=ioc_type, enable_live=enable_live)
            except Exception:
                results[val] = []

        return results

    def close(self):
        """Close the SQLite database connection for the calling thread."""
        conn = getattr(self._local, "conn", None)
        if conn is not None:
            try:
                conn.close()
            except Exception:
                pass
            self._local.conn = None

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()
