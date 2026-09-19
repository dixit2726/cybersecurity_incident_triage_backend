import os
import sys
from typing import Any, Dict, Optional

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

from src.nlp.alert_parser import AlertParser
from src.rag.multi_source_retriever import MultiSourceRetriever


class AlertRAGPipeline:
    """
    Alert-to-RAG Integration Pipeline.

    Accepts raw cybersecurity alerts, parses them into structured components
    (metadata, network context, situational context, IOCs, behavioral evidence),
    constructs a focused behavioral query, and queries the multi-source RAG
    orchestrator (MITRE ATT&CK, Incident Playbooks, CISA Guidance).

    CRITICAL BOUNDARY:
    This pipeline produces retrieval evidence and candidate matches only.
    It does NOT produce final security decisions (no confirmed attack, no final
    malicious/benign classification, no final severity override, and no final remediation).
    """

    def __init__(
        self,
        retriever: Optional[MultiSourceRetriever] = None,
        parser: Optional[AlertParser] = None,
    ):
        self.parser = parser or AlertParser()
        self.retriever = retriever or MultiSourceRetriever()

    def build_rag_query(self, parsed_alert: Dict[str, Any]) -> str:
        """
        Build a focused behavioral and contextual query from the parsed alert.

        Does NOT pass raw unparsed alert text. Incorporates:
        - Event type
        - Behavioral evidence extracted by parser
        - Situational context (target service, target account, attempts, time window)
        - Attack category

        Ensures all components are derived solely from parsed alert data.
        """
        parts = []

        metadata = parsed_alert.get("alert_metadata", {})
        context = parsed_alert.get("context", {})
        behavioral_evidence = parsed_alert.get("behavioral_evidence", [])

        # 1. Event Type
        event_type = metadata.get("event_type")
        if event_type:
            clean_et = event_type.strip().rstrip(".")
            parts.append(f"{clean_et}.")

        # 2. Behavioral Evidence (Required for MITRE behavioral query alignment)
        for ev in behavioral_evidence:
            ev_clean = ev.strip()
            if ev_clean:
                if not ev_clean.endswith((".", "!", "?")):
                    ev_clean += "."
                parts.append(ev_clean)

        # 3. Contextual details (service, account, attempt counts, duration)
        target_service = context.get("target_service")
        target_account = context.get("target_account")
        failed_attempts = context.get("failed_login_attempts")
        time_window = context.get("time_window")

        context_items = []
        if target_service:
            context_items.append(f"Target service {target_service}")
        if target_account:
            context_items.append(f"Target account {target_account}")
        if failed_attempts and not any(str(failed_attempts) in ev for ev in behavioral_evidence):
            context_items.append(f"{failed_attempts} failed authentication attempts")
        if time_window and not any(str(time_window) in ev for ev in behavioral_evidence):
            context_items.append(f"within {time_window}")

        if context_items:
            parts.append(". ".join(context_items) + ".")

        # 4. Attack Category (if distinct from event type)
        attack_category = metadata.get("attack_category")
        if attack_category and (not event_type or attack_category.lower() not in event_type.lower()):
            clean_cat = attack_category.strip().rstrip(".")
            parts.append(f"{clean_cat}.")

        # Fallback if no specific fields were captured
        if not parts:
            for k in ["event_type", "attack_category", "severity"]:
                val = metadata.get(k)
                if val:
                    parts.append(str(val))

        rag_query = " ".join(parts).strip()
        return rag_query

    def process_alert(
        self,
        alert_text: str,
        mitre_top_k: int = 5,
        playbook_top_k: int = 5,
        cisa_top_k: int = 5,
    ) -> Dict[str, Any]:
        """
        Execute full Alert -> Parser -> Query Generation -> Multi-Source RAG pipeline.

        Returns structured dictionary containing:
        - parsed_alert
        - rag_query
        - rag_results (mitre, playbooks, cisa, summary)
        """
        # Step 1: Deterministic alert parsing
        parsed_alert = self.parser.parse(alert_text)

        # Step 2: Build focused behavioral query
        rag_query = self.build_rag_query(parsed_alert)

        # Step 3: Multi-Source retrieval
        retrieval = self.retriever.retrieve(
            rag_query,
            mitre_top_k=mitre_top_k,
            playbook_top_k=playbook_top_k,
            cisa_top_k=cisa_top_k,
        )

        return {
            "parsed_alert": parsed_alert,
            "rag_query": rag_query,
            "rag_results": {
                "mitre": retrieval["mitre"],
                "playbooks": retrieval["playbooks"],
                "cisa": retrieval["cisa"],
                "summary": retrieval["summary"],
            },
        }
