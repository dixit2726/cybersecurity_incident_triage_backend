import ipaddress
import os
import re
from typing import Any, Dict, List, Optional
import requests
from dotenv import load_dotenv

load_dotenv()


def is_private_or_local_ip(ioc_value: str) -> bool:
    """
    Determine if an IOC is a private, loopback, link-local, or reserved IP address (RFC 1918, etc.).
    Protects internal infrastructure from being transmitted to external threat intelligence APIs.
    """
    if not isinstance(ioc_value, str) or not ioc_value.strip():
        return False

    clean_val = ioc_value.strip()

    # Extract host if IP:port format
    host = clean_val
    if ":" in host and not host.startswith("http://") and not host.startswith("https://"):
        host = host.split(":")[0]

    # Check for localhost names
    if host.lower() in ["localhost", "127.0.0.1", "::1"]:
        return True

    try:
        ip_obj = ipaddress.ip_address(host)
        return bool(
            ip_obj.is_private
            or ip_obj.is_loopback
            or ip_obj.is_reserved
            or ip_obj.is_link_local
            or ip_obj.is_multicast
        )
    except ValueError:
        # Not a valid standalone IP (could be URL, domain, or hash)
        return False


class AbuseCHClient:
    """
    Reusable, fail-safe REST client for Abuse.ch Threat Intelligence APIs:
    - ThreatFox (IP, Domain, URL, Hash indicators)
    - URLhaus (Malicious URLs and Hosts)
    - MalwareBazaar (Malware sample hashes)

    CRITICAL BOUNDARIES:
    - Zero leaks: Never logs or prints API keys.
    - Private IP Protection: Drops RFC 1918/loopback requests before network transmission.
    - Strict Timeouts: Default 3.0s timeout; non-blocking fail-safe architecture.
    - Resilient: Catches all connection errors, timeouts, and HTTP errors without crashing the pipeline.
    """

    THREATFOX_URL = "https://threatfox-api.abuse.ch/api/v1/"
    URLHAUS_URL_ENDPOINT = "https://urlhaus-api.abuse.ch/v1/url/"
    URLHAUS_HOST_ENDPOINT = "https://urlhaus-api.abuse.ch/v1/host/"
    MALWAREBAZAAR_URL = "https://mb-api.abuse.ch/api/v1/"

    def __init__(
        self,
        api_key: Optional[str] = None,
        timeout: float = 3.0,
    ):
        # Read API key strictly from environment if not passed explicitly
        self._api_key = api_key or os.getenv("ABUSE_CH_API_KEY", "").strip() or None
        self.timeout = timeout

    @property
    def has_api_key(self) -> bool:
        return bool(self._api_key)

    def _get_headers(self) -> Dict[str, str]:
        headers = {
            "User-Agent": "Cybersecurity-Incident-Triage-AI/1.0",
            "Accept": "application/json",
        }
        if self._api_key:
            headers["Auth-Key"] = self._api_key
        return headers

    # -------------------------------------------------------------------------
    # ThreatFox Lookup
    # -------------------------------------------------------------------------
    def query_threatfox(self, ioc: str) -> List[Dict[str, Any]]:
        """
        Query ThreatFox API for an IP, domain, URL, or hash.
        """
        if is_private_or_local_ip(ioc):
            return []

        payload = {
            "query": "search_ioc",
            "search_term": ioc.strip(),
        }

        try:
            response = requests.post(
                self.THREATFOX_URL,
                json=payload,
                headers=self._get_headers(),
                timeout=self.timeout,
            )
            if response.status_code != 200:
                return []

            data = response.json()
            if not isinstance(data, dict) or data.get("query_status") != "ok":
                return []

            raw_records = data.get("data", [])
            if not isinstance(raw_records, list):
                return []

            normalized_results: List[Dict[str, Any]] = []
            for item in raw_records:
                if not isinstance(item, dict):
                    continue

                tags_val = item.get("tags")
                if isinstance(tags_val, list):
                    tags_str = ", ".join(str(t) for t in tags_val if t)
                else:
                    tags_str = str(tags_val or "")

                normalized_results.append({
                    "ioc": item.get("ioc") or ioc,
                    "ioc_type": item.get("ioc_type") or "unknown",
                    "source": "ThreatFox",
                    "threat_type": item.get("threat_type") or "unknown",
                    "malware": item.get("malware_printable") or item.get("malware") or "",
                    "confidence": str(item.get("confidence_level", "")),
                    "tags": tags_str,
                    "reference": item.get("reference") or "",
                    "source_origin": "live",
                })

            return normalized_results

        except (requests.Timeout, requests.ConnectionError, requests.RequestException, ValueError):
            return []

    # -------------------------------------------------------------------------
    # URLhaus Lookup
    # -------------------------------------------------------------------------
    def query_urlhaus(self, ioc: str, is_url: bool = True) -> List[Dict[str, Any]]:
        """
        Query URLhaus API for a malicious URL or host.
        """
        if is_private_or_local_ip(ioc):
            return []

        clean_ioc = ioc.strip()
        url = self.URLHAUS_URL_ENDPOINT if is_url else self.URLHAUS_HOST_ENDPOINT
        data_payload = {"url": clean_ioc} if is_url else {"host": clean_ioc}

        try:
            response = requests.post(
                url,
                data=data_payload,
                headers=self._get_headers(),
                timeout=self.timeout,
            )
            if response.status_code != 200:
                return []

            data = response.json()
            if not isinstance(data, dict) or data.get("query_status") != "ok":
                return []

            tags_val = data.get("tags")
            if isinstance(tags_val, list):
                tags_str = ", ".join(str(t) for t in tags_val if t)
            else:
                tags_str = str(tags_val or "")

            return [{
                "ioc": data.get("url") or data.get("host") or clean_ioc,
                "ioc_type": "url" if is_url else "host",
                "source": "URLhaus",
                "threat_type": data.get("threat") or "malware_download",
                "malware": "",
                "confidence": "",
                "tags": tags_str,
                "reference": data.get("urlhaus_reference") or "",
                "source_origin": "live",
            }]

        except (requests.Timeout, requests.ConnectionError, requests.RequestException, ValueError):
            return []

    # -------------------------------------------------------------------------
    # MalwareBazaar Lookup
    # -------------------------------------------------------------------------
    def query_malwarebazaar(self, hash_value: str) -> List[Dict[str, Any]]:
        """
        Query MalwareBazaar API for an MD5, SHA1, or SHA256 file hash.
        """
        clean_hash = hash_value.strip().lower()

        payload = {
            "query": "get_info",
            "hash": clean_hash,
        }

        try:
            response = requests.post(
                self.MALWAREBAZAAR_URL,
                data=payload,
                headers=self._get_headers(),
                timeout=self.timeout,
            )
            if response.status_code != 200:
                return []

            data = response.json()
            if not isinstance(data, dict) or data.get("query_status") != "ok":
                return []

            raw_records = data.get("data", [])
            if not isinstance(raw_records, list):
                return []

            normalized_results: List[Dict[str, Any]] = []
            for item in raw_records:
                if not isinstance(item, dict):
                    continue

                tags_val = item.get("tags")
                if isinstance(tags_val, list):
                    tags_str = ", ".join(str(t) for t in tags_val if t)
                else:
                    tags_str = str(tags_val or "")

                sha256 = item.get("sha256_hash", "")
                reference = f"https://bazaar.abuse.ch/sample/{sha256}/" if sha256 else ""

                ioc_type = "md5_hash" if len(clean_hash) == 32 else ("sha1_hash" if len(clean_hash) == 40 else "sha256_hash")

                normalized_results.append({
                    "ioc": clean_hash,
                    "ioc_type": ioc_type,
                    "source": "MalwareBazaar",
                    "threat_type": item.get("file_type") or "malware_sample",
                    "malware": item.get("signature") or "",
                    "confidence": "",
                    "tags": tags_str,
                    "reference": reference,
                    "source_origin": "live",
                })

            return normalized_results

        except (requests.Timeout, requests.ConnectionError, requests.RequestException, ValueError):
            return []

    # -------------------------------------------------------------------------
    # Unified Lookup Dispatcher
    # -------------------------------------------------------------------------
    def lookup(self, ioc: str, ioc_type: Optional[str] = None) -> List[Dict[str, Any]]:
        """
        Unified lookup dispatching to appropriate Abuse.ch endpoints based on IOC type.
        Guarantees that private IPs are never queried externally.
        """
        if not isinstance(ioc, str) or not ioc.strip():
            return []

        clean_ioc = ioc.strip()

        # Enforce private IP filtering unconditionally
        if is_private_or_local_ip(clean_ioc):
            return []

        norm_type = (ioc_type or "").strip().lower()
        results: List[Dict[str, Any]] = []

        # 1. Hashes
        if norm_type in ["md5", "md5_hash", "sha1", "sha1_hash", "sha256", "sha256_hash", "hash"] or re.fullmatch(r"[a-fA-F0-9]{32,64}", clean_ioc):
            results.extend(self.query_malwarebazaar(clean_ioc))
            results.extend(self.query_threatfox(clean_ioc))

        # 2. URLs
        elif norm_type == "url" or clean_ioc.startswith("http://") or clean_ioc.startswith("https://"):
            results.extend(self.query_urlhaus(clean_ioc, is_url=True))
            results.extend(self.query_threatfox(clean_ioc))

        # 3. IPs and Domains
        else:
            # ThreatFox handles IP, IP:port, and domains
            results.extend(self.query_threatfox(clean_ioc))
            # If domain/host, query URLhaus host endpoint as well
            if norm_type in ["domain", "host"] or re.search(r"[a-zA-Z]", clean_ioc):
                results.extend(self.query_urlhaus(clean_ioc, is_url=False))

        return results
