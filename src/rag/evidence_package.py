import os
import sys
from typing import Any, Dict, List, Optional

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


class EvidencePackageBuilder:
    """
    Builds a clean, structured evidence package from the output of
    AlertParser and AlertRAGPipeline, enriched with local Threat Intelligence.

    CRITICAL BOUNDARY:
    - This package aggregates candidate evidence, retrieved guidance, and local TI matches only.
    - It does NOT make final security verdicts (no attack confirmation,
      no final severity verdict, no final MITRE selection, no remediation decision).
    - It does not call an LLM or live external threat intelligence APIs.
    - Similarity scores are kept source-specific without cross-source comparison.
    """

    def __init__(
        self,
        ti_service: Optional[ThreatIntelService] = None,
        enable_live: bool = False,
    ):
        self.enable_live = enable_live
        self.ti_service = ti_service or ThreatIntelService(enable_live=enable_live)

    def build(
        self,
        pipeline_result: Dict[str, Any],
        enable_live: Optional[bool] = None,
    ) -> Dict[str, Any]:
        """
        Transform raw pipeline output into a normalized Evidence Package.

        :param pipeline_result: Dict containing 'parsed_alert' and 'rag_results'
                                (from AlertRAGPipeline.process_alert).
        :param enable_live: Optional flag to enable live threat intelligence lookup.
                            Defaults to self.enable_live (False by default).
        :return: Standardized Evidence Package dictionary.
        """
        if not isinstance(pipeline_result, dict):
            raise TypeError("pipeline_result must be a dictionary.")

        parsed_alert = pipeline_result.get("parsed_alert", {})
        rag_results = pipeline_result.get("rag_results", {})

        # 1. Alert Information (preserving original metadata and context)
        alert_metadata = parsed_alert.get("alert_metadata", {})
        network_context = parsed_alert.get("network_context", {})
        context = parsed_alert.get("context", {})

        alert_section = {
            "alert_metadata": dict(alert_metadata),
            "network_context": dict(network_context),
            "context": dict(context),
        }

        # 2. Behavioral Evidence & IOC Evidence (strictly preserved)
        behavioral_evidence = list(parsed_alert.get("behavioral_evidence", []))
        ioc_evidence = list(parsed_alert.get("ioc_evidence", []))

        # 3. MITRE Candidates (Deduplicate by technique_id, keeping highest score)
        raw_mitre = rag_results.get("mitre", [])
        mitre_by_technique: Dict[str, Dict[str, Any]] = {}

        for item in raw_mitre:
            tech_id = item.get("technique_id")
            if not tech_id:
                continue

            score = float(item.get("score", 0.0))
            candidate = {
                "technique_id": tech_id,
                "technique_name": item.get("technique_name", ""),
                "score": score,
                "source": item.get("source", ""),
                "chunk_id": item.get("chunk_id", 0),
                "evidence_text": item.get("text") or item.get("evidence_text", ""),
            }

            if tech_id not in mitre_by_technique or score > mitre_by_technique[tech_id]["score"]:
                mitre_by_technique[tech_id] = candidate

        # Sort MITRE candidates by descending score
        mitre_candidates = sorted(
            mitre_by_technique.values(),
            key=lambda x: x["score"],
            reverse=True,
        )

        # 4. Playbook Evidence (Deduplicate by playbook_name + source, keeping highest score)
        raw_playbooks = rag_results.get("playbooks", [])
        playbooks_by_key: Dict[str, Dict[str, Any]] = {}

        for item in raw_playbooks:
            pb_name = item.get("playbook_name", "")
            pb_source = item.get("source", "")
            key = f"{pb_name}::{pb_source}"

            score = float(item.get("score", 0.0))
            evidence_entry = {
                "playbook_name": pb_name,
                "incident_type": item.get("incident_type", ""),
                "score": score,
                "source": pb_source,
                "chunk_id": item.get("chunk_id", 0),
                "evidence_text": item.get("text") or item.get("evidence_text", ""),
            }

            if key not in playbooks_by_key or score > playbooks_by_key[key]["score"]:
                playbooks_by_key[key] = evidence_entry

        # Sort Playbook evidence by descending score
        playbook_evidence = sorted(
            playbooks_by_key.values(),
            key=lambda x: x["score"],
            reverse=True,
        )

        # 5. CISA Evidence (Not aggressively deduplicated; preserve guidance chunks)
        raw_cisa = rag_results.get("cisa", [])
        cisa_evidence: List[Dict[str, Any]] = []

        for item in raw_cisa:
            cisa_entry = {
                "document_title": item.get("document_title", ""),
                "category": item.get("category", ""),
                "source_type": item.get("source_type", ""),
                "score": float(item.get("score", 0.0)),
                "source": item.get("source", ""),
                "chunk_id": item.get("chunk_id", 0),
                "evidence_text": item.get("text") or item.get("evidence_text", ""),
            }
            cisa_evidence.append(cisa_entry)

        # Sort CISA evidence by descending score
        cisa_evidence = sorted(
            cisa_evidence,
            key=lambda x: x["score"],
            reverse=True,
        )

        # 6. Local Threat Intelligence Enrichment
        threat_intelligence: List[Dict[str, Any]] = []
        total_ti_matches = 0

        # Type mapping from AlertParser IOC types to ThreatIntelService supported types
        type_mapping = {
            "ip": "ip",
            "ipv4": "ip",
            "ipv6": "ip",
            "url": "url",
            "domain": "domain",
            "md5": "md5_hash",
            "md5_hash": "md5_hash",
            "sha1": "sha1_hash",
            "sha1_hash": "sha1_hash",
            "sha256": "sha256_hash",
            "sha256_hash": "sha256_hash",
            "hash": "hash",
        }

        for ioc_item in ioc_evidence:
            raw_val = ioc_item.get("value")
            raw_type = ioc_item.get("type", "unknown")
            if not raw_val or not str(raw_val).strip():
                continue

            clean_val = str(raw_val).strip()
            norm_type_key = str(raw_type).strip().lower()
            mapped_type = type_mapping.get(norm_type_key)

            matches: List[Dict[str, Any]] = []
            if mapped_type:
                try:
                    matches = self.ti_service.lookup(
                        clean_val,
                        ioc_type=mapped_type,
                        enable_live=enable_live,
                    )
                except Exception:
                    matches = []
            else:
                # Unsupported by local database (e.g. email) - do not invent result
                matches = []

            match_found = len(matches) > 0
            total_ti_matches += len(matches)

            threat_intelligence.append({
                "queried_ioc": clean_val,
                "ioc_type": raw_type,
                "match_found": match_found,
                "matches": matches,
            })

        # 7. Evidence Summary
        evidence_summary = {
            "behavioral_evidence_count": len(behavioral_evidence),
            "ioc_count": len(ioc_evidence),
            "threat_intelligence_ioc_count": len(threat_intelligence),
            "threat_intelligence_match_count": total_ti_matches,
            "mitre_candidate_count": len(mitre_candidates),
            "playbook_evidence_count": len(playbook_evidence),
            "cisa_evidence_count": len(cisa_evidence),
        }

        return {
            "alert": alert_section,
            "behavioral_evidence": behavioral_evidence,
            "ioc_evidence": ioc_evidence,
            "threat_intelligence": threat_intelligence,
            "mitre_candidates": mitre_candidates,
            "playbook_evidence": playbook_evidence,
            "cisa_evidence": cisa_evidence,
            "evidence_summary": evidence_summary,
        }

