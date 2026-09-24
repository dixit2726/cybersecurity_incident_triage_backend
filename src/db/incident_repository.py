import logging
import uuid
from typing import Any, Dict, List, Optional
from datetime import datetime

from src.db.supabase_client import get_supabase_client

logger = logging.getLogger("db.incident_repository")


_DEFAULT_CLIENT = object()


class IncidentRepository:
    """
    Repository for persisting and querying incident triage analyses in Supabase PostgreSQL.
    Provides fail-safe database operations that never break or interrupt AI triage.
    """

    TABLE_NAME = "incidents"

    def __init__(self, client=_DEFAULT_CLIENT):
        self._custom_client = client

    @property
    def client(self):
        if self._custom_client is not _DEFAULT_CLIENT:
            return self._custom_client
        return get_supabase_client()

    def create_incident(
        self,
        alert_text: str,
        triage_report: Dict[str, Any],
        alert_id: Optional[str] = None,
        network_context: Optional[Dict[str, Any]] = None,
    ) -> Optional[Dict[str, Any]]:
        """
        Persist a synthesized incident triage report into the Supabase database.
        Returns the inserted record dict on success, or None on failure/unconfigured.
        Guaranteed NEVER to raise an exception.
        """
        sb = self.client
        if sb is None:
            logger.debug("Supabase client is not available. Skipping incident persistence.")
            return None

        try:
            # Extract fields defensively from triage_report and context
            net_ctx = network_context or {}
            sev_assessment = triage_report.get("severity_assessment", {})
            if isinstance(sev_assessment, dict):
                severity = sev_assessment.get("assessed_severity") or sev_assessment.get("alert_severity")
            else:
                severity = str(sev_assessment) if sev_assessment else None

            inc_id = alert_id or triage_report.get("alert_id")
            event_type = triage_report.get("event_type")

            # Extract source and destination IPs
            source_ip = net_ctx.get("source_ip")
            dest_ip = net_ctx.get("destination_ip")

            # Fallback IP extraction from ioc_findings if network_context is missing
            if not source_ip or not dest_ip:
                for ioc in triage_report.get("ioc_findings", []):
                    if isinstance(ioc, dict) and ioc.get("type") in ("ip", "ipv4"):
                        val = ioc.get("value") or ioc.get("ioc")
                        ctx = str(ioc.get("context", "")).lower()
                        if "source" in ctx or "attacker" in ctx or "external" in ctx:
                            if not source_ip:
                                source_ip = val
                        elif "destination" in ctx or "target" in ctx or "internal" in ctx:
                            if not dest_ip:
                                dest_ip = val

            dest_port = net_ctx.get("destination_port")
            dest_port_str = str(dest_port) if dest_port is not None else None

            payload = {
                "incident_id": inc_id,
                "alert_text": alert_text,
                "severity": severity,
                "event_type": event_type,
                "source_ip": source_ip,
                "destination_ip": dest_ip,
                "protocol": net_ctx.get("protocol"),
                "destination_port": dest_port_str,
                "iocs": triage_report.get("ioc_findings", []),
                "threat_intelligence": triage_report.get("threat_intelligence_findings", []),
                "mitre_results": triage_report.get("mitre_analysis", []),
                "playbooks": triage_report.get("playbook_recommendations", []),
                "cisa_guidance": triage_report.get("cisa_guidance", []),
                "triage_report": triage_report,
                "analyst_review_required": triage_report.get("analyst_review_required", True),
            }

            res = sb.table(self.TABLE_NAME).insert(payload).execute()
            if res.data and len(res.data) > 0:
                inserted = res.data[0]
                logger.info("Successfully persisted incident to Supabase (id: %s, incident_id: %s)", inserted.get("id"), inc_id)
                return inserted

            logger.warning("Supabase insert returned empty response.")
            return None

        except Exception as e:
            logger.warning("Failed to persist incident to Supabase (triage unaffected): %s", str(e))
            return None

    def get_incident(self, identifier: str) -> Optional[Dict[str, Any]]:
        """
        Retrieve a single incident by its UUID 'id' or textual 'incident_id'.
        Returns None if not found or if database query fails.
        """
        sb = self.client
        if sb is None or not identifier:
            return None

        try:
            # Check if identifier is a valid UUID
            is_uuid = False
            try:
                uuid.UUID(str(identifier))
                is_uuid = True
            except (ValueError, TypeError, AttributeError):
                is_uuid = False

            if is_uuid:
                res = sb.table(self.TABLE_NAME).select("*").eq("id", identifier).limit(1).execute()
            else:
                res = sb.table(self.TABLE_NAME).select("*").eq("incident_id", identifier).order("created_at", desc=True).limit(1).execute()

            if res.data and len(res.data) > 0:
                return res.data[0]
            return None

        except Exception as e:
            logger.warning("Error retrieving incident '%s' from Supabase: %s", identifier, str(e))
            return None

    def list_incidents(self, limit: int = 20, offset: int = 0) -> List[Dict[str, Any]]:
        """
        Retrieve a paginated list of stored incidents ordered by created_at descending.
        Excludes bulky full text/report columns to keep list queries fast and bandwidth-light.
        """
        sb = self.client
        if sb is None:
            return []

        limit = max(1, min(limit, 100))
        offset = max(0, offset)

        try:
            columns = (
                "id, incident_id, created_at, severity, event_type, "
                "source_ip, destination_ip, protocol, destination_port, "
                "analyst_review_required"
            )
            res = (
                sb.table(self.TABLE_NAME)
                .select(columns)
                .order("created_at", desc=True)
                .range(offset, offset + limit - 1)
                .execute()
            )
            return res.data or []

        except Exception as e:
            logger.warning("Error listing incidents from Supabase: %s", str(e))
            return []

    def count_incidents(self) -> int:
        """
        Return the total number of stored incidents.
        """
        sb = self.client
        if sb is None:
            return 0

        try:
            res = sb.table(self.TABLE_NAME).select("id", count="exact").limit(1).execute()
            return getattr(res, "count", None) or len(res.data or [])
        except Exception as e:
            logger.warning("Error counting incidents in Supabase: %s", str(e))
            return 0


# Global singleton repository instance
incident_repo = IncidentRepository()
