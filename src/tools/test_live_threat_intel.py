import io
import os
import sys
import unittest
from unittest.mock import MagicMock, patch
import requests

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

from src.tools.abusech_api_client import AbuseCHClient, is_private_or_local_ip
from src.tools.threat_intel_service import ThreatIntelService, deduplicate_matches


def run_tests():
    print("\n" + "=" * 60)
    print("LIVE THREAT INTELLIGENCE TEST SUITE")
    print("=" * 60)

    checks = []

    # -------------------------------------------------------------------------
    # TEST A: Existing Offline Lookup Still Works (Regression Guarantee)
    # -------------------------------------------------------------------------
    print("\n[TEST A] Existing Offline SQLite Lookup")
    print("-" * 60)
    service_offline = ThreatIntelService(enable_live=False)
    tf_ioc = "154.91.59.119:8084"
    offline_matches = service_offline.lookup(tf_ioc, ioc_type="ip:port")

    check_a = (
        len(offline_matches) > 0
        and offline_matches[0].get("source") == "ThreatFox"
        and offline_matches[0].get("source_origin") == "local"
    )
    print(f"Queried local IOC: {tf_ioc}")
    print(f"Matches found: {len(offline_matches)}")
    if offline_matches:
        print(f"Source origin: {offline_matches[0].get('source_origin')}")
    checks.append(("Existing offline lookup works and tags 'local'", check_a))

    # -------------------------------------------------------------------------
    # TEST B: Private IP Protection
    # -------------------------------------------------------------------------
    print("\n[TEST B] Private IP Protection")
    print("-" * 60)
    private_ips = ["10.10.25.14", "192.168.1.105", "127.0.0.1", "172.16.5.10", "localhost"]
    all_private_blocked = True

    with patch("requests.post") as mock_post:
        client = AbuseCHClient()
        for priv_ip in private_ips:
            res = client.lookup(priv_ip, ioc_type="ip")
            if res != [] or mock_post.called:
                all_private_blocked = False
                print(f"FAILED: Private IP {priv_ip} triggered external call or returned non-empty!")

    print(f"Tested private IPs: {private_ips}")
    print(f"External HTTP calls made: {mock_post.call_count} (Expected: 0)")
    check_b = all_private_blocked and mock_post.call_count == 0
    checks.append(("Private IP protection (no external calls made)", check_b))

    # -------------------------------------------------------------------------
    # TEST C: API Timeout Handling
    # -------------------------------------------------------------------------
    print("\n[TEST C] API Timeout Handling")
    print("-" * 60)
    with patch("requests.post", side_effect=requests.Timeout("Connection timed out")):
        client = AbuseCHClient()
        res_timeout = client.lookup("185.234.72.19", ioc_type="ip")

    check_c = (res_timeout == [])
    print(f"Timeout simulation result: {res_timeout} (Expected: [])")
    checks.append(("API timeout caught gracefully without crashing", check_c))

    # -------------------------------------------------------------------------
    # TEST D: API Connection Failure Handling
    # -------------------------------------------------------------------------
    print("\n[TEST D] API Connection Failure Handling")
    print("-" * 60)
    with patch("requests.post", side_effect=requests.ConnectionError("Failed to resolve host")):
        client = AbuseCHClient()
        res_conn = client.lookup("185.234.72.19", ioc_type="ip")

    check_d = (res_conn == [])
    print(f"Connection error simulation result: {res_conn} (Expected: [])")
    checks.append(("API connection error caught gracefully without crashing", check_d))

    # -------------------------------------------------------------------------
    # TEST E: Malformed API Response Handling
    # -------------------------------------------------------------------------
    print("\n[TEST E] Malformed API Response Handling")
    print("-" * 60)
    mock_resp_malformed = MagicMock()
    mock_resp_malformed.status_code = 200
    mock_resp_malformed.json.side_effect = ValueError("Invalid JSON string")

    with patch("requests.post", return_value=mock_resp_malformed):
        client = AbuseCHClient()
        res_malformed = client.lookup("185.234.72.19", ioc_type="ip")

    check_e = (res_malformed == [])
    print(f"Malformed JSON simulation result: {res_malformed} (Expected: [])")
    checks.append(("Malformed API response handled safely", check_e))

    # -------------------------------------------------------------------------
    # TEST F: Live Response Normalization
    # -------------------------------------------------------------------------
    print("\n[TEST F] Live Response Normalization")
    print("-" * 60)
    mock_tf_data = {
        "query_status": "ok",
        "data": [
            {
                "id": "12345",
                "ioc": "185.234.72.19:22",
                "threat_type": "botnet_cc",
                "ioc_type": "ip:port",
                "malware": "mirai",
                "malware_printable": "Mirai",
                "confidence_level": 95,
                "tags": ["mirai", "scanner"],
                "reference": "https://threatfox.abuse.ch/ioc/12345/",
            }
        ],
    }
    mock_resp_tf = MagicMock()
    mock_resp_tf.status_code = 200
    mock_resp_tf.json.return_value = mock_tf_data

    with patch("requests.post", return_value=mock_resp_tf):
        client = AbuseCHClient()
        live_norm_results = client.query_threatfox("185.234.72.19")

    check_f = False
    required_keys = {"ioc", "ioc_type", "source", "threat_type", "malware", "confidence", "tags", "reference", "source_origin"}
    if len(live_norm_results) == 1:
        record = live_norm_results[0]
        check_f = (
            required_keys.issubset(set(record.keys()))
            and record["source"] == "ThreatFox"
            and record["source_origin"] == "live"
            and record["malware"] == "Mirai"
            and record["confidence"] == "95"
        )
        print(f"Normalized Live Record: {record}")
    checks.append(("Live response normalization matches schema exactly", check_f))

    # -------------------------------------------------------------------------
    # TEST G: Local + Live Result Merging
    # -------------------------------------------------------------------------
    print("\n[TEST G] Local + Live Result Merging")
    print("-" * 60)
    # Mock live client returning a mock live record for a known local IOC
    mock_client = MagicMock()
    mock_client.lookup.return_value = [
        {
            "ioc": "154.91.59.119:8084",
            "ioc_type": "ip:port",
            "source": "ThreatFox",
            "threat_type": "botnet_cc",
            "malware": "VShell_Live_Enriched",
            "confidence": "100",
            "tags": "live_feed",
            "reference": "https://threatfox.abuse.ch/ioc/999/",
            "source_origin": "live",
        }
    ]

    service_hybrid = ThreatIntelService(enable_live=True, live_client=mock_client)
    hybrid_matches = service_hybrid.lookup("154.91.59.119", ioc_type="ip")

    origins = {m.get("source_origin") for m in hybrid_matches}
    check_g = ("local" in origins and "live" in origins)
    print(f"Total merged matches: {len(hybrid_matches)}")
    print(f"Encountered origins: {origins}")
    checks.append(("Local and Live results merged successfully", check_g))

    # -------------------------------------------------------------------------
    # TEST H: Deduplication
    # -------------------------------------------------------------------------
    print("\n[TEST H] Deduplication by (source, ioc, threat_type, malware)")
    print("-" * 60)
    duplicate_candidates = [
        {"source": "ThreatFox", "ioc": "1.2.3.4", "threat_type": "botnet", "malware": "Mirai", "source_origin": "local"},
        {"source": "ThreatFox", "ioc": "1.2.3.4", "threat_type": "botnet", "malware": "Mirai", "source_origin": "live"}, # Duplicate!
        {"source": "ThreatFox", "ioc": "1.2.3.4", "threat_type": "c2", "malware": "Mirai", "source_origin": "live"}, # Different threat_type
    ]
    deduped = deduplicate_matches(duplicate_candidates)
    check_h = (len(deduped) == 2 and deduped[0]["source_origin"] == "local")
    print(f"Input records: {len(duplicate_candidates)} -> Deduplicated records: {len(deduped)}")
    checks.append(("Deduplication preserves uniqueness and priority", check_h))

    # -------------------------------------------------------------------------
    # TEST I: API Key Protection (Zero Leakage)
    # -------------------------------------------------------------------------
    print("\n[TEST I] API Key Protection (Never Printed)")
    print("-" * 60)
    secret_key = "ABUSE_CH_SUPER_SECRET_TOKEN_987654321"

    # Capture stdout during initialization and query
    old_stdout = sys.stdout
    captured_io = io.StringIO()
    try:
        sys.stdout = captured_io
        client_sec = AbuseCHClient(api_key=secret_key)
        with patch("requests.post") as mock_sec_post:
            mock_sec_post.return_value.status_code = 200
            mock_sec_post.return_value.json.return_value = {"query_status": "no_result"}
            client_sec.lookup("8.8.8.8", ioc_type="ip")
    finally:
        sys.stdout = old_stdout

    captured_logs = captured_io.getvalue()
    check_i = (secret_key not in captured_logs)
    print(f"Secret API key leaked in stdout: {not check_i}")
    checks.append(("API Key is never printed or exposed to stdout", check_i))

    # -------------------------------------------------------------------------
    # SUMMARY
    # -------------------------------------------------------------------------
    print("\n" + "=" * 60)
    print("VALIDATION SUMMARY")
    print("=" * 60)
    all_passed = True
    for label, status in checks:
        state = "[PASS]" if status else "[FAIL]"
        print(f"{state:7} {label}")
        if not status:
            all_passed = False

    print("=" * 60)
    if all_passed:
        print("Live Threat Intelligence Test Suite: PASSED")
    else:
        print("Live Threat Intelligence Test Suite: FAILED")
    print("=" * 60)

    # Optional Real API invocation if configured
    if "--real-api" in sys.argv:
        print("\n" + "=" * 60)
        print("MANUAL REAL ABUSE.CH API TEST")
        print("=" * 60)
        real_client = AbuseCHClient()
        if not real_client.has_api_key:
            print("Note: Running unauthenticated or with public rate limits (no ABUSE_CH_API_KEY in env).")
        print("Querying real ThreatFox for test IOC: 154.91.59.119 ...")
        real_results = real_client.lookup("154.91.59.119")
        print(f"Real API response count: {len(real_results)}")
        if real_results:
            print(f"Sample Real Result: {real_results[0]}")
        print("=" * 60)

    return all_passed


if __name__ == "__main__":
    success = run_tests()
    sys.exit(0 if success else 1)
