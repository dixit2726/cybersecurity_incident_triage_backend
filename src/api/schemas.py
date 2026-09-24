from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field, field_validator


class TriageRequest(BaseModel):
    """
    Input schema for incident triage requests.
    Accepts one complete, raw cybersecurity alert text.
    The user/frontend does not have to provide separate IOC or behavioral fields.
    """
    alert_text: str = Field(
        ...,
        description="Complete raw cybersecurity alert text to triage.",
        max_length=100000,
        examples=[
            "ALERT_ID: SEC-2026-0915-001\n"
            "Timestamp: 2026-09-15 10:32:11\n"
            "Severity: High\n"
            "Event Type: Brute Force Attack\n"
            "Source IP: 185.234.72.19\n"
            "Destination IP: 10.10.25.14\n"
            "Protocol: TCP\n"
            "Destination Port: 22\n\n"
            "Multiple failed SSH authentication attempts detected.\n"
            "47 failed authentication attempts were recorded within 5 minutes.\n"
            "5 different usernames were targeted.\n"
            "No successful login was detected."
        ],
    )
    enable_live: bool = Field(
        default=False,
        description="Toggle live external threat intelligence enrichment (Abuse.ch). Default is false.",
    )

    @field_validator("alert_text")
    @classmethod
    def validate_alert_text(cls, v: str) -> str:
        if not isinstance(v, str) or not v.strip():
            raise ValueError("alert_text must not be empty or whitespace-only.")
        return v


class ProcessingMetadata(BaseModel):
    """
    Safe execution metadata for tracking performance without leaking internal paths or keys.
    """
    processing_time_ms: float = Field(
        ...,
        description="Total triage processing duration in milliseconds."
    )


class TriageResponse(BaseModel):
    """
    Top-level API response envelope.
    Preserves the complete structured Incident Triage Report produced by Gemini.
    """
    success: bool = Field(
        default=True,
        description="Indicates successful completion of the triage workflow."
    )
    alert_id: Optional[str] = Field(
        default=None,
        description="Extracted unique incident/alert identifier if present in the alert."
    )
    triage_report: Dict[str, Any] = Field(
        ...,
        description="Structured Incident Triage Report containing all 12 standardized sections."
    )
    processing_metadata: Optional[ProcessingMetadata] = Field(
        default=None,
        description="Non-sensitive operational performance metadata."
    )


class HealthResponse(BaseModel):
    """
    API health status response.
    """
    status: str = Field(
        default="healthy",
        description="Current health status of the service."
    )


class RootResponse(BaseModel):
    """
    Root service information response.
    """
    service: str = Field(
        default="Cybersecurity Incident Triage AI",
        description="Service name."
    )
    version: str = Field(
        default="1.0.0",
        description="Semantic API version."
    )
    status: str = Field(
        default="running",
        description="Current running state."
    )


class IncidentAskRequest(BaseModel):
    """
    Input schema for asking questions scoped strictly to an analyzed incident.
    """
    triage_report: Dict[str, Any] = Field(
        ...,
        description="Structured Incident Triage Report produced from prior triage."
    )
    question: str = Field(
        ...,
        min_length=1,
        max_length=2000,
        description="Analyst question regarding the current analyzed incident.",
        examples=["Why was this alert assessed as High severity?"]
    )
    alert_text: Optional[str] = Field(
        default=None,
        max_length=100000,
        description="Optional original alert text for additional context."
    )

    @field_validator("question")
    @classmethod
    def validate_question(cls, v: str) -> str:
        if not isinstance(v, str) or not v.strip():
            raise ValueError("question must not be empty or whitespace-only.")
        return v.strip()


class IncidentAskResponse(BaseModel):
    """
    Response schema for incident-scoped AI assistant answers.
    """
    success: bool = Field(
        default=True,
        description="Indicates whether the question was processed successfully."
    )
    question: str = Field(
        ...,
        description="Original question asked by the analyst."
    )
    answer: str = Field(
        ...,
        description="Evidence-grounded answer structured into explicit categories."
    )
    grounding: Dict[str, Any] = Field(
        default_factory=dict,
        description="Grounded evidence references derived strictly from the incident data."
    )


class IncidentSummary(BaseModel):
    """
    Lightweight summary representation of a stored incident for history listings.
    """
    id: str = Field(..., description="Unique database UUID identifier.")
    incident_id: Optional[str] = Field(default=None, description="Extracted alert/incident identifier.")
    created_at: Optional[str] = Field(default=None, description="Timestamp of when the incident was triaged.")
    severity: Optional[str] = Field(default=None, description="Assessed severity level.")
    event_type: Optional[str] = Field(default=None, description="Detected attack or event category.")
    source_ip: Optional[str] = Field(default=None, description="Identified source IP address.")
    destination_ip: Optional[str] = Field(default=None, description="Identified destination/target IP address.")
    protocol: Optional[str] = Field(default=None, description="Observed network protocol.")
    destination_port: Optional[str] = Field(default=None, description="Target port/service.")
    analyst_review_required: bool = Field(default=True, description="Human analyst verification flag.")


class IncidentListResponse(BaseModel):
    """
    Paginated incident list response envelope.
    """
    success: bool = Field(default=True, description="Query execution status.")
    total: int = Field(default=0, description="Total number of stored incidents.")
    limit: int = Field(default=20, description="Page limit requested.")
    offset: int = Field(default=0, description="Page offset requested.")
    incidents: List[IncidentSummary] = Field(default_factory=list, description="List of stored incident summaries.")


class IncidentDetailResponse(BaseModel):
    """
    Detailed incident record response envelope containing the full triage report.
    """
    success: bool = Field(default=True, description="Query execution status.")
    incident: Dict[str, Any] = Field(..., description="Complete stored incident record including full triage_report.")

