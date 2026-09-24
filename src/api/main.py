import logging
import os
import sys
import time
from datetime import datetime
from contextlib import asynccontextmanager
from typing import Any, Dict, Optional

# Ensure project root is in sys.path
PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

# Safely handle Windows console encodings
if hasattr(sys.stdout, "reconfigure"):
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

from fastapi import Depends, FastAPI, HTTPException, Request, status
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from starlette.concurrency import run_in_threadpool

from src.agent.triage_agent import TriageAgent
from src.api.dependencies import get_triage_agent
from src.api.schemas import (
    HealthResponse,
    IncidentAskRequest,
    IncidentAskResponse,
    IncidentDetailResponse,
    IncidentListResponse,
    IncidentSummary,
    ProcessingMetadata,
    RootResponse,
    TriageRequest,
    TriageResponse,
)
from src.db.incident_repository import incident_repo
from src.nlp.alert_parser import AlertParser

# Configure server logger
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
logger = logging.getLogger("api.main")


@asynccontextmanager
async def lifespan(app: FastAPI):
    """
    Application Lifespan Context Manager.
    Initializes the heavy TriageAgent (loading MITRE, Playbook, and CISA
    retrievers and FAISS indices) ONCE during application startup.
    Keeps the service in memory to serve incoming requests with low latency.
    """
    logger.info("Initializing TriageAgent singleton during startup...")
    # Initialize only if not already injected (e.g., during tests)
    if not hasattr(app.state, "triage_agent") or app.state.triage_agent is None:
        app.state.triage_agent = TriageAgent()
    logger.info("TriageAgent singleton initialized and ready.")
    yield
    logger.info("Shutting down Cybersecurity Incident Triage AI API.")


app = FastAPI(
    title="Cybersecurity Incident Triage AI API",
    version="1.0.0",
    description=(
        "REST API for the Cybersecurity Incident Triage AI system. "
        "Provides deterministic alert parsing, multi-source RAG retrieval "
        "(MITRE ATT&CK, Incident Response Playbooks, CISA Guidance), local and "
        "live threat intelligence enrichment, and evidence-grounded incident "
        "triage synthesis using Google Gemini."
    ),
    lifespan=lifespan,
    docs_url="/docs",
    redoc_url="/redoc",
    openapi_url="/openapi.json",
)

# -----------------------------------------------------------------------------
# CORS Middleware
# -----------------------------------------------------------------------------
allowed_origins = [
    "http://localhost:3000",
    "http://localhost:5173",
    "http://127.0.0.1:3000",
    "http://127.0.0.1:5173",
]
env_origins = os.getenv("ALLOWED_ORIGINS", "").strip()
if env_origins:
    allowed_origins.extend([o.strip() for o in env_origins.split(",") if o.strip()])

app.add_middleware(
    CORSMiddleware,
    allow_origins=allowed_origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# -----------------------------------------------------------------------------
# Safe Error Handlers
# -----------------------------------------------------------------------------
@app.exception_handler(RequestValidationError)
async def validation_exception_handler(request: Request, exc: RequestValidationError):
    """
    Sanitized handler for Pydantic validation errors (HTTP 422).
    Ensures no internal paths or sensitive runtime information is leaked.
    """
    errors = []
    for err in exc.errors():
        field = " -> ".join(str(loc) for loc in err.get("loc", []))
        errors.append({
            "field": field,
            "message": err.get("msg", "Invalid input."),
        })
    return JSONResponse(
        status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
        content={
            "detail": "Invalid or unprocessable request payload.",
            "errors": errors,
        },
    )


@app.exception_handler(ValueError)
async def value_error_handler(request: Request, exc: ValueError):
    """
    Handles alert parsing / validation ValueErrors as HTTP 422.
    """
    return JSONResponse(
        status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
        content={
            "detail": str(exc),
        },
    )


@app.exception_handler(Exception)
async def general_exception_handler(request: Request, exc: Exception):
    """
    Catches unexpected internal server exceptions.
    Logs error server-side while returning a safe HTTP 500 without leaking
    stack traces, filesystem paths, API keys, or database credentials.
    """
    logger.error("Unhandled internal server exception: %s", exc, exc_info=True)
    return JSONResponse(
        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        content={
            "detail": "Internal server error occurred during alert triage.",
        },
    )


# -----------------------------------------------------------------------------
# Endpoints
# -----------------------------------------------------------------------------
@app.get(
    "/",
    response_model=RootResponse,
    tags=["General"],
    summary="Root Service Information",
    description="Returns service metadata and current operating status.",
)
async def root() -> Dict[str, str]:
    return {
        "service": "Cybersecurity Incident Triage AI",
        "version": "1.0.0",
        "status": "running",
    }


@app.get(
    "/health",
    response_model=HealthResponse,
    tags=["General"],
    summary="Health Check",
    description="Returns operational health status for container and monitoring probes.",
)
async def health() -> Dict[str, str]:
    return {
        "status": "healthy",
    }


@app.post(
    "/api/v1/triage",
    response_model=TriageResponse,
    tags=["Incident Triage"],
    summary="Triage Cybersecurity Alert",
    description=(
        "Accepts one complete raw cybersecurity alert text. Executes deterministic "
        "parsing, multi-source RAG retrieval, threat intelligence lookup, and "
        "synthesizes an evidence-grounded triage report. Returns the structured "
        "triage report containing all 12 standardized sections."
    ),
)
async def triage_alert(
    request: TriageRequest,
    agent: TriageAgent = Depends(get_triage_agent),
) -> TriageResponse:
    start_time = time.perf_counter()
    req_start_str = datetime.now().strftime("%H:%M:%S.%f")[:-3]
    print(f"\n{'='*60}\n[Stage 1] Request received: start={req_start_str}\n{'='*60}")
    logger.info("[Stage 1] Request received: start=%s", req_start_str)

    # Execute triage through the singleton TriageAgent asynchronously in threadpool
    triage_report = await run_in_threadpool(
        agent.triage,
        alert_text=request.alert_text,
        enable_live=request.enable_live,
    )

    stage_timings: Dict[str, Any] = {}
    if isinstance(triage_report, dict) and "_stage_timings" in triage_report:
        stage_timings = triage_report.pop("_stage_timings")

    # Extract alert_id if available
    alert_id: Optional[str] = None
    if isinstance(triage_report, dict):
        alert_id = triage_report.get("alert_id")

    if not alert_id:
        try:
            parser = getattr(agent.rag_pipeline, "parser", None) or AlertParser()
            parsed = parser.parse(request.alert_text)
            alert_id = parsed.get("alert_metadata", {}).get("alert_id")
        except Exception:
            alert_id = None

    # 9. Final response serialization
    t_ser_start = time.perf_counter()
    ser_start_str = datetime.now().strftime("%H:%M:%S.%f")[:-3]
    elapsed_ms = (time.perf_counter() - start_time) * 1000.0

    response = TriageResponse(
        success=True,
        alert_id=alert_id,
        triage_report=triage_report,
        processing_metadata=ProcessingMetadata(
            processing_time_ms=round(elapsed_ms, 2)
        ),
    )
    t_ser_end = time.perf_counter()
    ser_end_str = datetime.now().strftime("%H:%M:%S.%f")[:-3]
    dur_ser_ms = (t_ser_end - t_ser_start) * 1000.0
    print(f"[Stage 9] Final response serialization: start={ser_start_str}, end={ser_end_str}, duration={dur_ser_ms:.2f} ms")

    # 10. Total request time
    total_end = time.perf_counter()
    total_req_ms = (total_end - start_time) * 1000.0
    print(f"[Stage 10] Total request time: duration={total_req_ms:.2f} ms")

    parse_ms = stage_timings.get("parsing", {}).get("ms", 0.0)
    ti_ms = stage_timings.get("threat_intel", {}).get("ms", 0.0)
    emb_ms = stage_timings.get("embedding", {}).get("ms", 0.0)
    mitre_ms = stage_timings.get("mitre_rag", {}).get("ms", 0.0)
    pb_ms = stage_timings.get("playbook_rag", {}).get("ms", 0.0)
    cisa_ms = stage_timings.get("cisa_rag", {}).get("ms", 0.0)
    ep_ms = stage_timings.get("evidence_package", {}).get("ms", 0.0)
    gem_ms = stage_timings.get("gemini", {}).get("ms", 0.0)

    summary_banner = f"""
==================================================
BACKEND REQUEST LATENCY BREAKDOWN (POST /api/v1/triage)
==================================================
Parsing:          {parse_ms:8.2f} ms
Threat Intel:     {ti_ms:8.2f} ms
MITRE RAG:        {mitre_ms + emb_ms:8.2f} ms  (Gemini Embedding: {emb_ms:.2f} ms, FAISS search: {mitre_ms:.2f} ms)
Playbook RAG:     {pb_ms:8.2f} ms
CISA RAG:         {cisa_ms:8.2f} ms
Evidence Package: {ep_ms:8.2f} ms
Gemini:           {gem_ms:8.2f} ms
Final Serializ.:  {dur_ser_ms:8.2f} ms
--------------------------------------------------
Total:            {total_req_ms:8.2f} ms
==================================================
"""
    print(summary_banner)
    logger.info(summary_banner)

    # Fail-safe asynchronous Supabase persistence (database error never breaks triage)
    try:
        network_ctx = None
        if hasattr(agent, "rag_pipeline") and hasattr(agent.rag_pipeline, "parser"):
            try:
                parsed_alert_for_ctx = agent.rag_pipeline.parser.parse(request.alert_text)
                network_ctx = parsed_alert_for_ctx.get("network_context")
            except Exception:
                pass

        await run_in_threadpool(
            incident_repo.create_incident,
            alert_text=request.alert_text,
            triage_report=triage_report,
            alert_id=alert_id,
            network_context=network_ctx,
        )
    except Exception as db_err:
        logger.warning("Failed to persist incident to Supabase (triage unaffected): %s", str(db_err))

    return response


@app.post(
    "/api/v1/incident/ask",
    response_model=IncidentAskResponse,
    tags=["Incident Assistant"],
    summary="Ask Question About Analyzed Incident",
    description=(
        "Scoped strictly to the current analyzed incident. Answers the analyst's "
        "question using only facts from the incident triage report and retrieved "
        "RAG guidance. Categorizes answers into Incident Evidence, RAG Evidence, "
        "AI Interpretation, Uncertainty, and Analyst Review."
    ),
)
async def ask_incident_question(
    request: IncidentAskRequest,
    agent: TriageAgent = Depends(get_triage_agent),
) -> IncidentAskResponse:
    try:
        # Delegate to the evidence-grounded incident assistant asynchronously in threadpool
        result = await run_in_threadpool(
            agent.gemini_engine.ask_question_over_incident,
            triage_report=request.triage_report,
            question=request.question,
            alert_text=request.alert_text,
        )

        return IncidentAskResponse(
            success=True,
            question=result.get("question", request.question),
            answer=result.get("answer", "The available incident evidence does not establish this."),
            grounding=result.get("grounding", {}),
        )
    except ValueError as ve:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=str(ve),
        )
    except Exception as e:
        logger.error("Error answering incident question: %s", e, exc_info=True)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="An error occurred while processing the incident question.",
        )


@app.get(
    "/api/v1/incidents",
    response_model=IncidentListResponse,
    tags=["Incident History"],
    summary="List Triaged Incidents",
    description="Retrieve a paginated list of historically triaged incidents from Supabase.",
)
async def list_incidents(
    limit: int = 20,
    offset: int = 0,
) -> IncidentListResponse:
    try:
        limit_clamped = max(1, min(limit, 100))
        offset_clamped = max(0, offset)
        items = await run_in_threadpool(
            incident_repo.list_incidents,
            limit=limit_clamped,
            offset=offset_clamped,
        )
        total = await run_in_threadpool(incident_repo.count_incidents)
        return IncidentListResponse(
            success=True,
            total=total,
            limit=limit_clamped,
            offset=offset_clamped,
            incidents=items,
        )
    except Exception as e:
        logger.warning("Error fetching incident history: %s", str(e))
        return IncidentListResponse(
            success=False,
            total=0,
            limit=limit,
            offset=offset,
            incidents=[],
        )


@app.get(
    "/api/v1/incidents/{incident_id}",
    response_model=IncidentDetailResponse,
    tags=["Incident History"],
    summary="Get Triaged Incident Details",
    description="Retrieve the complete stored incident record and triage report by ID or UUID.",
)
async def get_incident(
    incident_id: str,
) -> IncidentDetailResponse:
    try:
        record = await run_in_threadpool(
            incident_repo.get_incident,
            identifier=incident_id,
        )
        if not record:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Incident '{incident_id}' not found.",
            )
        return IncidentDetailResponse(
            success=True,
            incident=record,
        )
    except HTTPException:
        raise
    except Exception as e:
        logger.warning("Error retrieving incident '%s': %s", incident_id, str(e))
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to retrieve incident details from database.",
        )


if __name__ == "__main__":
    import uvicorn
    uvicorn.run("src.api.main:app", host="127.0.0.1", port=8000, reload=False)
