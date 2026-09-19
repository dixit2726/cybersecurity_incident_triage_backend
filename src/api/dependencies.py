import os
import sys
from typing import Optional
from fastapi import Request

# Ensure project root is in sys.path
PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from src.agent.triage_agent import TriageAgent


def get_triage_agent(request: Request) -> TriageAgent:
    """
    FastAPI dependency returning the application-level singleton TriageAgent.
    Ensures that RAG vector stores (MITRE, Playbooks, CISA) and embedding
    models are initialized once during startup and reused across requests.
    """
    agent: Optional[TriageAgent] = getattr(request.app.state, "triage_agent", None)
    if agent is None:
        # Fallback initialization for testing or situations where lifespan was bypassed
        agent = TriageAgent()
        request.app.state.triage_agent = agent
    return agent
