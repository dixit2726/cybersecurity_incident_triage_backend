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
        import time
        from datetime import datetime

        timings: Dict[str, Any] = {}

        # 2. Alert parsing
        t_parse_start = time.perf_counter()
        t_parse_start_str = datetime.now().strftime("%H:%M:%S.%f")[:-3]
        parsed_alert = self.rag_pipeline.parser.parse(alert_text)
        rag_query = self.rag_pipeline.build_rag_query(parsed_alert)
        t_parse_end = time.perf_counter()
        t_parse_end_str = datetime.now().strftime("%H:%M:%S.%f")[:-3]
        dur_parse_ms = (t_parse_end - t_parse_start) * 1000.0
        timings["parsing"] = {
            "start": t_parse_start_str, "end": t_parse_end_str, "ms": dur_parse_ms
        }
        print(f"[Stage 2] Alert parsing: start={t_parse_start_str}, end={t_parse_end_str}, duration={dur_parse_ms:.2f} ms")

        # Sub-stage: Gemini Embedding API
        t_emb_start = time.perf_counter()
        t_emb_start_str = datetime.now().strftime("%H:%M:%S.%f")[:-3]
        query_vector = self.rag_pipeline.retriever.embedding_provider.embed_text(rag_query)
        t_emb_end = time.perf_counter()
        t_emb_end_str = datetime.now().strftime("%H:%M:%S.%f")[:-3]
        dur_emb_ms = (t_emb_end - t_emb_start) * 1000.0
        timings["embedding"] = {
            "start": t_emb_start_str, "end": t_emb_end_str, "ms": dur_emb_ms
        }
        print(f"[Sub-stage] Gemini Embedding API: start={t_emb_start_str}, end={t_emb_end_str}, duration={dur_emb_ms:.2f} ms")

        # 4. MITRE RAG retrieval (FAISS search)
        t_mitre_start = time.perf_counter()
        t_mitre_start_str = datetime.now().strftime("%H:%M:%S.%f")[:-3]
        mitre_results = self.rag_pipeline.retriever.mitre_retriever.search_by_vector(query_vector, top_k=mitre_top_k)
        t_mitre_end = time.perf_counter()
        t_mitre_end_str = datetime.now().strftime("%H:%M:%S.%f")[:-3]
        dur_mitre_ms = (t_mitre_end - t_mitre_start) * 1000.0
        timings["mitre_rag"] = {
            "start": t_mitre_start_str, "end": t_mitre_end_str, "ms": dur_mitre_ms
        }
        print(f"[Stage 4] MITRE RAG retrieval: start={t_mitre_start_str}, end={t_mitre_end_str}, duration={dur_mitre_ms:.2f} ms")

        # 5. Playbook RAG retrieval (FAISS search)
        t_pb_start = time.perf_counter()
        t_pb_start_str = datetime.now().strftime("%H:%M:%S.%f")[:-3]
        playbook_results = self.rag_pipeline.retriever.playbook_retriever.search_by_vector(query_vector, top_k=playbook_top_k)
        t_pb_end = time.perf_counter()
        t_pb_end_str = datetime.now().strftime("%H:%M:%S.%f")[:-3]
        dur_pb_ms = (t_pb_end - t_pb_start) * 1000.0
        timings["playbook_rag"] = {
            "start": t_pb_start_str, "end": t_pb_end_str, "ms": dur_pb_ms
        }
        print(f"[Stage 5] Playbook RAG retrieval: start={t_pb_start_str}, end={t_pb_end_str}, duration={dur_pb_ms:.2f} ms")

        # 6. CISA RAG retrieval (FAISS search)
        t_cisa_start = time.perf_counter()
        t_cisa_start_str = datetime.now().strftime("%H:%M:%S.%f")[:-3]
        cisa_results = self.rag_pipeline.retriever.cisa_retriever.search_by_vector(query_vector, top_k=cisa_top_k)
        t_cisa_end = time.perf_counter()
        t_cisa_end_str = datetime.now().strftime("%H:%M:%S.%f")[:-3]
        dur_cisa_ms = (t_cisa_end - t_cisa_start) * 1000.0
        timings["cisa_rag"] = {
            "start": t_cisa_start_str, "end": t_cisa_end_str, "ms": dur_cisa_ms
        }
        print(f"[Stage 6] CISA RAG retrieval: start={t_cisa_start_str}, end={t_cisa_end_str}, duration={dur_cisa_ms:.2f} ms")

        # Normalize retrieval results
        retrieval = self.rag_pipeline.retriever.retrieve_by_vector(
            query_vector,
            query=rag_query,
            mitre_top_k=mitre_top_k,
            playbook_top_k=playbook_top_k,
            cisa_top_k=cisa_top_k,
        )
        pipeline_result = {
            "parsed_alert": parsed_alert,
            "rag_query": rag_query,
            "rag_results": {
                "mitre": retrieval["mitre"],
                "playbooks": retrieval["playbooks"],
                "cisa": retrieval["cisa"],
                "summary": retrieval["summary"],
            },
        }

        # 3. Threat Intelligence lookup & 7. Evidence package construction
        live_enabled = self.enable_live if enable_live is None else enable_live
        t_build_start = time.perf_counter()
        t_build_start_str = datetime.now().strftime("%H:%M:%S.%f")[:-3]
        evidence_pkg = self.evidence_builder.build(
            pipeline_result=pipeline_result,
            enable_live=live_enabled,
        )
        t_build_end = time.perf_counter()
        t_build_end_str = datetime.now().strftime("%H:%M:%S.%f")[:-3]
        dur_build_ms = (t_build_end - t_build_start) * 1000.0

        # Measure isolated TI lookup time
        t_ti_only_start = time.perf_counter()
        for ioc in parsed_alert.get("ioc_evidence", []):
            val = ioc.get("value")
            if val:
                try:
                    self.evidence_builder.ti_service.lookup(val, ioc_type=ioc.get("type"), enable_live=live_enabled)
                except Exception:
                    pass
        t_ti_only_end = time.perf_counter()
        dur_ti_ms = (t_ti_only_end - t_ti_only_start) * 1000.0
        dur_ep_ms = max(0.01, dur_build_ms - dur_ti_ms)

        timings["threat_intel"] = {
            "start": t_build_start_str, "end": t_build_end_str, "ms": dur_ti_ms
        }
        print(f"[Stage 3] Threat Intelligence lookup: start={t_build_start_str}, end={t_build_end_str}, duration={dur_ti_ms:.2f} ms")

        timings["evidence_package"] = {
            "start": t_build_start_str, "end": t_build_end_str, "ms": dur_ep_ms
        }
        print(f"[Stage 7] Evidence package construction: start={t_build_start_str}, end={t_build_end_str}, duration={dur_ep_ms:.2f} ms")

        # 8. Gemini triage analysis
        t_gem_start = time.perf_counter()
        t_gem_start_str = datetime.now().strftime("%H:%M:%S.%f")[:-3]
        report = self.gemini_engine.reason_over_evidence(evidence_pkg)
        t_gem_end = time.perf_counter()
        t_gem_end_str = datetime.now().strftime("%H:%M:%S.%f")[:-3]
        dur_gem_ms = (t_gem_end - t_gem_start) * 1000.0
        timings["gemini"] = {
            "start": t_gem_start_str, "end": t_gem_end_str, "ms": dur_gem_ms
        }
        print(f"[Stage 8] Gemini triage analysis: start={t_gem_start_str}, end={t_gem_end_str}, duration={dur_gem_ms:.2f} ms")

        if isinstance(report, dict):
            report = self.gemini_engine.reconcile_threat_intelligence(report, evidence_pkg)
            report["_stage_timings"] = timings
        return report

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