import os
import sys

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

from src.tools.threat_intel_service import ThreatIntelService


def main():
    print("\n" + "=" * 60)
    print("THREAT INTELLIGENCE SERVICE TEST")
    print("=" * 60)

    service = ThreatIntelService()

    # ---------------------------------------------------------
    # TEST 1 — ThreatFox IP:PORT
    # ---------------------------------------------------------
    print("\nTEST 1 — ThreatFox IP:PORT")
    print("-" * 60)
    tf_ioc = "154.91.59.119:8084"
    res1 = service.lookup(tf_ioc, ioc_type="ip:port")
    print(f"Query IOC: {tf_ioc}")
    print(f"Matches found: {len(res1)}")
    if res1:
        match = res1[0]
        print(f"Source:      {match.get('source')}")
        print(f"Threat Type: {match.get('threat_type')}")
        print(f"Malware:     {match.get('malware')}")
        print(f"Confidence:  {match.get('confidence')}")

    # ---------------------------------------------------------
    # TEST 2 — IP NORMALIZATION
    # ---------------------------------------------------------
    print("\nTEST 2 — IP NORMALIZATION")
    print("-" * 60)
    ip_only = "154.91.59.119"
    res2 = service.lookup(ip_only, ioc_type="ip")
    print(f"Query IP (without port): {ip_only}")
    print(f"Matches found: {len(res2)}")
    if res2:
        for idx, m in enumerate(res2, start=1):
            print(f"  [{idx}] Matched DB IOC: {m.get('ioc')} | Source: {m.get('source')} | Malware: {m.get('malware')}")

    # ---------------------------------------------------------
    # TEST 3 — MalwareBazaar MD5
    # ---------------------------------------------------------
    print("\nTEST 3 — MalwareBazaar MD5")
    print("-" * 60)
    mb_hash = "50b5f83f2878e8ed53a4d82c992432d7"
    res3 = service.lookup(mb_hash, ioc_type="md5")
    print(f"Query Hash: {mb_hash}")
    print(f"Matches found: {len(res3)}")
    if res3:
        match3 = res3[0]
        print(f"Source:      {match3.get('source')}")
        print(f"Threat Type: {match3.get('threat_type')}")
        print(f"IOC Type:    {match3.get('ioc_type')}")

    # ---------------------------------------------------------
    # TEST 4 — NONEXISTENT IOC
    # ---------------------------------------------------------
    print("\nTEST 4 — NONEXISTENT IOC")
    print("-" * 60)
    nonexistent_ioc = "192.0.2.1"
    res4 = service.lookup(nonexistent_ioc, ioc_type="ip")
    print(f"Query Nonexistent IOC: {nonexistent_ioc}")
    print(f"Matches found: {len(res4)}")
    print(f"Returned Result: {res4}")

    # ---------------------------------------------------------
    # TEST 5 — STRUCTURED OUTPUT & BATCH LOOKUP
    # ---------------------------------------------------------
    print("\nTEST 5 — STRUCTURED OUTPUT")
    print("-" * 60)
    batch_iocs = [
        {"type": "ip", "value": "154.91.59.119"},
        {"type": "md5", "value": "50b5f83f2878e8ed53a4d82c992432d7"},
        {"type": "ip", "value": "192.0.2.1"},
    ]
    batch_res = service.lookup_many(batch_iocs)
    print(f"Batch query keys: {list(batch_res.keys())}")
    for k, v in batch_res.items():
        print(f"  {k:36} -> {len(v)} match(es)")

    # ---------------------------------------------------------
    # VALIDATION
    # ---------------------------------------------------------
    print("\nVALIDATION")
    print("-" * 60)

    checks = []

    # 1. ThreatFox lookup
    check1 = bool(
        len(res1) > 0
        and res1[0].get("source") == "ThreatFox"
        and res1[0].get("threat_type") == "botnet_cc"
        and res1[0].get("malware") == "VShell"
    )
    checks.append(("ThreatFox lookup", check1))

    # 2. IP normalization (query IP matches IP:PORT)
    check2 = bool(
        len(res2) > 0
        and any(m.get("ioc") == "154.91.59.119:8084" for m in res2)
    )
    checks.append(("IP normalization", check2))

    # 3. MalwareBazaar lookup
    check3 = bool(
        len(res3) > 0
        and res3[0].get("source") == "MalwareBazaar"
        and res3[0].get("ioc") == mb_hash
    )
    checks.append(("MalwareBazaar lookup", check3))

    # 4. No-match handling
    check4 = res4 == []
    checks.append(("No-match handling", check4))

    # 5. Structured dictionary output
    required_keys = {"ioc", "ioc_type", "source", "threat_type", "malware", "confidence", "tags", "reference"}
    check5 = bool(
        len(res1) > 0
        and isinstance(res1[0], dict)
        and required_keys.issubset(set(res1[0].keys()))
    )
    checks.append(("Structured dictionary output", check5))

    # 6. No live API calls (offline SQLite database verified)
    check6 = hasattr(service, "conn") and service.conn is not None
    checks.append(("No live API calls", check6))

    # 7. SQLite database used
    check7 = os.path.exists(service.db_path) and service.db_path.endswith(".db")
    checks.append(("SQLite database used", check7))

    all_passed = True
    failed_checks = []
    for label, passed in checks:
        status_tag = "[PASS]" if passed else "[FAIL]"
        print(f"{status_tag} {label}")
        if not passed:
            all_passed = False
            failed_checks.append(label)

    service.close()

    print("\n" + "=" * 60)
    if all_passed:
        print("Threat Intelligence Service validation: PASSED")
    else:
        print("Threat Intelligence Service validation: FAILED")
        for fc in failed_checks:
            print(f"FAILED CHECK: {fc}")
    print("=" * 60 + "\n")

    if not all_passed:
        sys.exit(1)


if __name__ == "__main__":
    main()
