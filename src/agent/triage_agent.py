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

from src.rag.alert_rag_pipeline import AlertRAGPipeline
from src.rag.evidence_package import EvidencePackageBuilder
from src.tools.threat_intel_service import ThreatIntelService
from src.tools.abusech_api_client import is_private_or_local_ip
from src.tools.threatfox_tool import threatfox_lookup
from src.tools.urlhaus_tool import urlhaus_lookup
from src.tools.malwarebazaar_tool import malwarebazaar_lookup


def get_tool_for_ioc(ioc_type: str):
    """
    Select the correct threat-intelligence tool based on IOC type.
    Maintained for downstream tool-calling compatibility.
    """
    if ioc_type in ["ip", "ip:port"]:
        return threatfox_lookup
    elif ioc_type in ["url", "domain"]:
        return urlhaus_lookup
    elif ioc_type in ["md5_hash", "sha1_hash", "sha256_hash", "hash", "md5", "sha1", "sha256"]:
        return malwarebazaar_lookup
    return None


from src.agent.gemini_triage_engine import GeminiTriageEngine


class TriageAgent:
    """
    Cybersecurity Incident Triage Orchestrator Agent.
    Coordinates deterministic alert parsing, multi-source RAG retrieval
    (MITRE ATT&CK, Incident Response Playbooks, CISA Guidance), local and
    optional live threat intelligence enrichment, and evidence aggregation.

    CRITICAL BOUNDARIES:
    - Pure orchestration and evidence gathering layer.
    - Strictly preserves factual evidence without inventing IOCs, behaviors, or findings.
    - Operates over the immutable Evidence Package for Gemini reasoning.
    - Treats similarity scores as source-specific retrieval ranks, NOT confidence percentages.
    - Enforces private IP filtering before external threat intelligence calls.
    - Failure of external APIs or LLMs does not crash the orchestration pipeline.
    """

    def __init__(
        self,
        rag_pipeline: Optional[AlertRAGPipeline] = None,
        evidence_builder: Optional[EvidencePackageBuilder] = None,
        gemini_engine: Optional[GeminiTriageEngine] = None,
        enable_live: bool = False,
    ):
        self.rag_pipeline = rag_pipeline or AlertRAGPipeline()
        self.evidence_builder = evidence_builder or EvidencePackageBuilder(enable_live=enable_live)
        self.enable_live = enable_live
        self.gemini_engine = gemini_engine or GeminiTriageEngine()

    def triage(
        self,
        alert_text: str,
        enable_live: Optional[bool] = None,
        mitre_top_k: int = 5,
        playbook_top_k: int = 5,
        cisa_top_k: int = 5,
    ) -> Dict[str, Any]:
        """
        Execute End-to-End Incident Triage with Gemini Evidence-Based Reasoning:
        Alert -> Parsing -> Multi-Source RAG -> Threat Intel -> Evidence Package -> Gemini -> Final Report.

        :param alert_text: Raw cybersecurity alert string.
        :param enable_live: Optional toggle for live threat intelligence lookup.
        :param mitre_top_k: Number of MITRE candidates to retrieve (default 5).
        :param playbook_top_k: Number of Playbook candidates to retrieve (default 5).
        :param cisa_top_k: Number of CISA guidance candidates to retrieve (default 5).
        :return: Final structured Incident Triage Report synthesized by Gemini from the Evidence Package.
        """
        evidence_pkg = self.process_alert(
            alert_text=alert_text,
            enable_live=enable_live,
            mitre_top_k=mitre_top_k,
            playbook_top_k=playbook_top_k,
            cisa_top_k=cisa_top_k,
        )
        return self.gemini_engine.reason_over_evidence(evidence_pkg)

    def process_alert(
        self,
        alert_text: str,
        enable_live: Optional[bool] = None,
        mitre_top_k: int = 5,
        playbook_top_k: int = 5,
        cisa_top_k: int = 5,
    ) -> Dict[str, Any]:
        """
        Orchestrate complete alert triage workflow:
        1. Accept raw alert text.
        2. Parse alert deterministically via AlertParser.
        3. Extract behavioral evidence and IOCs.
        4. Construct focused behavioral query and retrieve from MITRE, Playbooks, and CISA RAG stores.
        5. Query Threat Intelligence (local SQLite and optional live Abuse.ch).
        6. Aggregate into normalized Evidence Package.
        7. Return complete, controlled investigation context.

        :param alert_text: Raw cybersecurity alert string.
        :param enable_live: Optional toggle for live threat intelligence lookup (defaults to self.enable_live).
        :param mitre_top_k: Number of MITRE candidates to retrieve (default 5).
        :param playbook_top_k: Number of Playbook candidates to retrieve (default 5).
        :param cisa_top_k: Number of CISA guidance candidates to retrieve (default 5).
        :return: Standardized orchestrated triage evidence dictionary.
        """
        if not isinstance(alert_text, str) or not alert_text.strip():
            raise ValueError("Alert input must be a non-empty string.")

        live_enabled = self.enable_live if enable_live is None else enable_live

        # Step 1-4: Parse alert, construct query, and retrieve multi-source RAG context
        pipeline_result = self.rag_pipeline.process_alert(
            alert_text=alert_text,
            mitre_top_k=mitre_top_k,
            playbook_top_k=playbook_top_k,
            cisa_top_k=cisa_top_k,
        )

        # Step 5-6: Query Threat Intelligence and assemble normalized Evidence Package
        evidence_pkg = self.evidence_builder.build(
            pipeline_result=pipeline_result,
            enable_live=live_enabled,
        )

        # Step 7: Return comprehensive orchestrated context
        return {
            "alert": evidence_pkg["alert"],
            "parsed_alert": pipeline_result["parsed_alert"],
            "rag_query": pipeline_result["rag_query"],
            "behavioral_evidence": evidence_pkg["behavioral_evidence"],
            "ioc_evidence": evidence_pkg["ioc_evidence"],
            "threat_intelligence": evidence_pkg["threat_intelligence"],
            "mitre_candidates": evidence_pkg["mitre_candidates"],
            "playbook_evidence": evidence_pkg["playbook_evidence"],
            "cisa_evidence": evidence_pkg["cisa_evidence"],
            "evidence_summary": evidence_pkg["evidence_summary"],
        }