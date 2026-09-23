import json
import logging
import os
import re
import sys
from typing import Any, Dict, List, Optional
from dotenv import load_dotenv

load_dotenv()

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

logger = logging.getLogger("agent.gemini_triage_engine")


def sanitize_secret(text: Any, secret_key: Optional[str] = None) -> str:
    """Scrub potential API keys or credentials from strings before logging or reporting."""
    if not text:
        return ""
    s = str(text)
    if secret_key and len(secret_key) > 5:
        s = s.replace(secret_key, "[REDACTED_API_KEY]")
    # Redact Google API key patterns: AIzaSy..., AQ....
    s = re.sub(r"AIza[0-9A-Za-z-_]{35}", "[REDACTED_API_KEY]", s)
    s = re.sub(r"AQ\.[0-9A-Za-z-_]{40,}", "[REDACTED_API_KEY]", s)
    # Redact xKiro / OpenAI key patterns: sk-...
    s = re.sub(r"sk-[0-9A-Za-z-_]{20,}", "[REDACTED_API_KEY]", s)
    # Redact key=... parameters in URLs or JSON
    s = re.sub(r"(key[=:][\s\"']*)[A-Za-z0-9_\-\.]{20,}", r"\1[REDACTED_API_KEY]", s, flags=re.IGNORECASE)
    return s


def classify_gemini_error(error: Any, secret_key: Optional[str] = None) -> Dict[str, str]:
    """
    Classify Gemini API errors into clean user-facing categories:
    - 503 Service Unavailable / High demand
    - 429 Quota / Rate limit
    - 401 Authentication failure
    - General / Other service error

    Returns a dict with:
    - code: '503', '429', '401', 'NOT_CONFIGURED', 'PARSE_ERROR', 'GENERAL'
    - category: Machine-readable category
    - user_assessment: Clean message for incident_assessment
    - limitation: Clean message for limitations list
    - technical_detail: Sanitized technical log string (for server-side logging only)
    """
    raw_str = sanitize_secret(str(error), secret_key)
    err_lower = raw_str.lower()

    # Check status code attributes if exception object has status_code or code
    status_code = getattr(error, "status_code", None) or getattr(error, "code", None)
    status_code_str = str(status_code) if status_code is not None else ""

    # Specific non-API internal conditions
    if "not set" in err_lower or "not initialized" in err_lower:
        return {
            "code": "NOT_CONFIGURED",
            "category": "CLIENT_NOT_INITIALIZED",
            "user_assessment": f"AI reasoning layer was unavailable ({raw_str}). Controlled evidence preserved directly from Evidence Package.",
            "limitation": f"AI reasoning unavailable: {raw_str}",
            "technical_detail": raw_str,
        }

    if "valid json dictionary" in err_lower:
        return {
            "code": "PARSE_ERROR",
            "category": "INVALID_RESPONSE_FORMAT",
            "user_assessment": "AI reasoning layer was unavailable (response format validation failed). Controlled evidence preserved directly from Evidence Package.",
            "limitation": "AI reasoning unavailable: LLM response did not produce a valid JSON dictionary.",
            "technical_detail": raw_str,
        }

    # 1. 503 Service Unavailable / High Demand / Overloaded
    # Note: Check 503 before generic resource exhausted if 503 is in status or text
    is_503 = (
        status_code_str == "503"
        or "503" in err_lower
        or "unavailable" in err_lower
        or "high demand" in err_lower
        or "model is overloaded" in err_lower
        or "temporarily experiencing high demand" in err_lower
    )

    # 2. 401 Authentication Failure
    is_401 = (
        status_code_str in ("401", "403")
        or "401" in err_lower
        or "unauthenticated" in err_lower
        or "api_key_invalid" in err_lower
        or "api key not valid" in err_lower
        or "invalid api key" in err_lower
    )

    # 3. 429 Rate Limit / Quota Exhaustion
    is_429 = (
        status_code_str == "429"
        or "429" in err_lower
        or "resource_exhausted" in err_lower
        or "resourceexhausted" in err_lower
        or "quota" in err_lower
        or "rate limit" in err_lower
        or "too many requests" in err_lower
    )

    if is_503:
        return {
            "code": "503",
            "category": "SERVICE_UNAVAILABLE",
            "user_assessment": (
                "AI reasoning temporarily unavailable. The Gemini model is temporarily unavailable. "
                "Collected security evidence has been preserved. Please retry shortly. "
                "AI reasoning layer was unavailable due to upstream service capacity (HTTP 503 Unavailable)."
            ),
            "limitation": "AI reasoning unavailable: Gemini model temporarily experiencing high demand (HTTP 503 Unavailable).",
            "technical_detail": raw_str,
        }
    elif is_401:
        return {
            "code": "401",
            "category": "AUTHENTICATION_FAILURE",
            "user_assessment": (
                "AI reasoning layer was unavailable due to authentication failure. "
                "Collected security evidence has been preserved. Please verify configured API credentials."
            ),
            "limitation": "AI reasoning unavailable: Gemini authentication failure (HTTP 401 / Invalid Credentials).",
            "technical_detail": raw_str,
        }
    elif is_429:
        return {
            "code": "429",
            "category": "RATE_LIMIT_EXCEEDED",
            "user_assessment": (
                "AI reasoning layer was unavailable due to API rate limits or quota exhaustion. "
                "Collected security evidence has been preserved. Please retry after quota replenishment."
            ),
            "limitation": "AI reasoning unavailable: Gemini API rate limit or quota exceeded (HTTP 429).",
            "technical_detail": raw_str,
        }
    else:
        return {
            "code": "GENERAL",
            "category": "GENERAL_ERROR",
            "user_assessment": (
                "AI reasoning layer was unavailable due to an unexpected service error. "
                "Collected security evidence has been preserved. Please retry shortly."
            ),
            "limitation": "AI reasoning unavailable: Gemini service invocation error.",
            "technical_detail": raw_str,
        }


def clean_json_response(raw_text: str) -> str:
    """
    Extract JSON payload from LLM response text, stripping markdown blocks if present.
    """
    text = raw_text.strip()
    # Strip markdown code blocks ```json ... ```
    if text.startswith("```"):
        text = re.sub(r"^```(?:json)?\s*", "", text, flags=re.IGNORECASE)
        text = re.sub(r"\s*```$", "", text)
    # Find outer bracket bounds
    start = text.find("{")
    end = text.rfind("}")
    if start != -1 and end != -1 and end > start:
        return text[start : end + 1]
    return text


class OpenAIResponse:
    """Lightweight response wrapper mimicking LangChain's AIMessage."""

    def __init__(self, content: str):
        self.content = content


class OpenAICompatibleClient:
    """
    Lightweight client for OpenAI-compatible chat completion APIs (e.g., xKiro, OpenRouter).
    Exposes an `.invoke(prompt)` method returning an object with a `.content` attribute.
    """

    def __init__(
        self,
        api_key: str,
        base_url: str = "https://api.xkiro.com/v1",
        model: str = "qwen/qwen3.5-flash:free",
        temperature: float = 0.1,
        timeout: float = 45.0,
        max_retries: int = 0,
        max_tokens: int = 2048,
    ):
        self.api_key = api_key
        self.base_url = base_url.rstrip("/")
        self.model = model
        self.temperature = temperature
        self.timeout = timeout
        self.max_retries = max_retries
        self.max_tokens = max_tokens

    def invoke(self, prompt: str) -> OpenAIResponse:
        import requests

        url = f"{self.base_url}/chat/completions"
        headers = {
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type": "application/json",
        }
        payload = {
            "model": self.model,
            "messages": [
                {"role": "user", "content": prompt}
            ],
            "temperature": self.temperature,
            "max_tokens": self.max_tokens,
        }

        last_error = None
        for attempt in range(max(1, self.max_retries + 1)):
            try:
                resp = requests.post(url, headers=headers, json=payload, timeout=self.timeout)
                if resp.status_code == 200:
                    data = resp.json()
                    choices = data.get("choices", [])
                    if choices and "message" in choices[0]:
                        content = choices[0]["message"].get("content", "")
                        return OpenAIResponse(content=content)
                    raise ValueError(f"Invalid completion format from API: {data}")
                else:
                    error_msg = f"HTTP {resp.status_code}: {resp.text}"
                    last_error = RuntimeError(error_msg)
            except Exception as e:
                last_error = e

        raise last_error or RuntimeError("OpenAI-compatible chat completion failed")


class GeminiTriageEngine:
    """
    Evidence-based AI reasoning engine powered by Google Gemini or OpenAI-compatible providers (e.g. xKiro).
    Ingests an immutable Evidence Package and performs structured, grounded triage.

    CRITICAL BOUNDARIES:
    - Never receives unparsed/uncontrolled alerts: Operates strictly over Evidence Package.
    - Zero Hallucination Policy: Does not invent IOCs, attack behavior, or findings.
    - Strict MITRE Verification: Classifies candidates as SUPPORTED, PLAUSIBLE, or NOT_SUPPORTED.
    - Evidence Isolation: Treats similarity scores as retrieval ranks, NOT confidence percentages.
    - Threat Intelligence Context: TI no-match means not found in queried DB, NOT proven safe.
    - Preserves Uncertainty: Retains original severity unless conclusive evidence demands change.
    - Human-in-the-Loop: Always flags analyst_review_required=True.
    - Zero API Key Leaks: Never prints, logs, or returns API keys.
    - Fail-Safe: Catches all LLM invocation errors gracefully without crashing the pipeline.
    """

    SYSTEM_PROMPT = """You are an expert, disciplined SOC Incident Triage AI Assistant.
Your task is to analyze the supplied cybersecurity Evidence Package and produce a rigorous, structured Incident Triage Report.

CRITICAL OPERATIONAL RULES:
1. STRICT EVIDENCE GROUNDING:
   - Base your assessment ONLY on the facts, indicators, and retrieved content present in the Evidence Package.
   - NEVER invent IOCs, threat actor names, malware families, attacker activities, or remediation actions that are not directly supported by the Evidence Package.
   - Distinguish strictly between:
     a) DIRECT EVIDENCE (extracted from the alert itself, such as failed login counts or target IPs)
     b) RETRIEVED EVIDENCE (matches from MITRE, Playbooks, CISA, or Threat Intelligence databases)
     c) INFERENCE (logical deductions drawn strictly from the evidence)
     d) UNCERTAINTY (gaps in visibility, missing telemetry, or inconclusive findings)

2. MITRE ATT&CK EVALUATION RULE:
   - Retrieved MITRE techniques are CANDIDATES only, ranked by vector similarity. Similarity scores MUST NEVER be treated as confidence percentages.
   - You must evaluate EACH candidate technique against the incident's explicit behavioral evidence.
   - Classify each technique as:
     * "SUPPORTED": Explicit behavioral evidence directly confirms this activity (e.g. multiple failed SSH attempts directly supports T1110 Brute Force).
     * "PLAUSIBLE": Behavior aligns conceptually, but critical telemetry is missing to confirm (e.g. T1110.003 Password Spraying if multiple accounts targeted across short window).
     * "NOT_SUPPORTED": The alert contains no evidence indicating this activity occurred (e.g. SSH Hijacking T1563.001 if no active session existed or was hijacked).
   - For any technique marked NOT_SUPPORTED, explicitly state why and do not confirm it.

3. THREAT INTELLIGENCE INTERPRETATION RULE:
   - A Threat Intelligence match indicates the IOC was previously cataloged in that specific database.
   - A Threat Intelligence no-match ("match_found": false) indicates the indicator was not found in the local/queried dataset; it does NOT mean the indicator is benign or safe.
   - A match on an external IP does not automatically confirm compromise of the internal destination.
   - Internal RFC 1918 IPs (e.g. 10.0.0.0/8, 192.168.0.0/16) are protected and must not be flagged as external threats.

4. PLAYBOOK & CISA GUIDANCE RULE:
   - Ground response recommendations strictly in the retrieved Playbook procedures and CISA guidelines provided in the Evidence Package.
   - Do not invent hypothetical containment steps outside the scope of the evidence.

5. SEVERITY & UNCERTAINTY RULE:
   - Compare the alert's initial severity with the confirmed evidence.
   - If there is insufficient evidence to definitively upgrade or downgrade severity, explicitly state that the original alert severity is retained pending analyst review.
   - Always set "analyst_review_required": true because the human SOC analyst makes the final decision.
   - Explicitly list known limitations and visibility gaps.

OUTPUT FORMAT:
You MUST respond with valid JSON matching this exact structure:
{
    "alert_summary": "<concise factual summary of the alert>",
    "incident_assessment": "<evidence-grounded narrative explaining what occurred and current status>",
    "severity_assessment": {
        "alert_severity": "<original severity>",
        "assessed_severity": "<HIGH|MEDIUM|LOW|INFORMATIONAL>",
        "justification": "<detailed justification comparing alert severity with evidence>"
    },
    "behavioral_evidence": ["<direct evidence item 1>", "<direct evidence item 2>"],
    "ioc_findings": [
        {
            "ioc": "<value>",
            "type": "<type>",
            "context": "<role in incident, e.g. external source attacker vs internal server>"
        }
    ],
    "threat_intelligence_findings": [
        {
            "ioc": "<value>",
            "source": "<source>",
            "match_found": true,
            "interpretation": "<factual meaning of match or no-match>"
        }
    ],
    "mitre_analysis": [
        {
            "technique_id": "<id>",
            "technique_name": "<name>",
            "assessment": "SUPPORTED",
            "reason": "<clear reasoning>",
            "evidence": ["<behavioral evidence item>"]
        }
    ],
    "playbook_recommendations": ["<actionable step from playbook>"],
    "cisa_guidance": ["<actionable guideline from CISA>"],
    "recommended_actions": ["<prioritized list of containment/investigation steps>"],
    "analyst_review_required": true,
    "limitations": ["<gap or missing visibility 1>", "<gap 2>"]
}
"""

    def __init__(
        self,
        model_name: Optional[str] = None,
        api_key: Optional[str] = None,
        llm_client: Optional[Any] = None,
        max_retries: int = 0,
        timeout: float = 45.0,
        provider: Optional[str] = None,
        base_url: Optional[str] = None,
    ):
        # Determine provider: 'xkiro' or 'gemini'
        self.provider = (provider or os.getenv("LLM_PROVIDER", "gemini")).strip().lower()
        self._api_key = api_key or os.getenv("GOOGLE_API_KEY", "").strip() or os.getenv("GEMINI_API_KEY", "").strip() or None
        self._xkiro_key = os.getenv("XKIRO_API_KEY", "").strip() or None
        self._xkiro_base_url = (base_url or os.getenv("XKIRO_BASE_URL", "https://api.xkiro.com/v1")).strip()
        self._xkiro_model = (model_name if self.provider == "xkiro" else None) or os.getenv("XKIRO_MODEL", "qwen/qwen3.5-flash:free").strip()
        self.model_name = model_name or (self._xkiro_model if self.provider == "xkiro" else os.getenv("GEMINI_MODEL", "gemini-3.6-flash")).strip()
        self.max_retries = max_retries
        self.timeout = timeout
        self.llm_client = llm_client

    @property
    def has_api_key(self) -> bool:
        if self.provider == "xkiro":
            return bool(self._xkiro_key)
        return bool(self._api_key)

    @property
    def active_secret_key(self) -> Optional[str]:
        if self.provider == "xkiro":
            return self._xkiro_key
        return self._api_key

    def _initialize_client(self):
        """Lazy-initialize chat model client based on configured provider."""
        if self.llm_client is not None:
            return self.llm_client

        if self.provider == "xkiro":
            if not self._xkiro_key:
                logger.warning("xKiro provider requested but XKIRO_API_KEY is not set.")
                return None
            try:
                self.llm_client = OpenAICompatibleClient(
                    api_key=self._xkiro_key,
                    base_url=self._xkiro_base_url,
                    model=self._xkiro_model,
                    temperature=0.1,
                    timeout=self.timeout,
                    max_retries=self.max_retries,
                )
                return self.llm_client
            except Exception as e:
                logger.error("Failed to initialize xKiro client: %s", e)
                return None

        # Default Gemini client
        if not self._api_key:
            return None

        try:
            from langchain_google_genai import ChatGoogleGenerativeAI
            self.llm_client = ChatGoogleGenerativeAI(
                model=self.model_name,
                google_api_key=self._api_key,
                temperature=0.1,
                max_retries=self.max_retries,
                timeout=self.timeout,
            )
            return self.llm_client
        except Exception:
            return None

    def build_prompt(self, evidence_package: Dict[str, Any]) -> str:
        """
        Construct clean, formatted context from the Evidence Package.
        Ensures NO raw or uncontrolled prompt injection occurs.
        """
        # Sanitize evidence package for prompt inclusion (stripping any accidental keys)
        safe_evidence = {
            "alert": evidence_package.get("alert", {}),
            "behavioral_evidence": evidence_package.get("behavioral_evidence", []),
            "ioc_evidence": evidence_package.get("ioc_evidence", []),
            "threat_intelligence": evidence_package.get("threat_intelligence", []),
            "mitre_candidates": evidence_package.get("mitre_candidates", []),
            "playbook_evidence": evidence_package.get("playbook_evidence", []),
            "cisa_evidence": evidence_package.get("cisa_evidence", []),
        }

        return f"""{self.SYSTEM_PROMPT}

EVIDENCE PACKAGE:
{json.dumps(safe_evidence, indent=2)}

INSTRUCTIONS:
Generate the JSON triage report strictly adhering to the schema and grounding rules above.
Respond ONLY with the JSON object, no Markdown backticks or commentary."""

    def generate_fallback_report(
        self,
        evidence_package: Dict[str, Any],
        error_message: Optional[str] = None,
        classified_error: Optional[Dict[str, str]] = None,
    ) -> Dict[str, Any]:
        """
        Generate a safe, structured fallback report when Gemini is unavailable or errors.
        Guarantees that the pipeline never crashes, preserves the Evidence Package,
        and avoids exposing raw exception dumps to the user.
        """
        if classified_error is None:
            classified_error = classify_gemini_error(error_message or "Unknown error", secret_key=self.active_secret_key)

        alert_meta = evidence_package.get("alert", {}).get("alert_metadata", {})
        net_ctx = evidence_package.get("alert", {}).get("network_context", {})

        # Parse behavioral and IOC items
        behavioral_ev = evidence_package.get("behavioral_evidence", [])
        iocs = evidence_package.get("ioc_evidence", [])
        ti_list = evidence_package.get("threat_intelligence", [])

        # Format IOC findings
        ioc_findings = []
        for ioc in iocs:
            val = ioc.get("value", "")
            ioc_findings.append({
                "ioc": val,
                "type": ioc.get("type", "unknown"),
                "context": f"Network participant in {net_ctx.get('protocol', 'network')} traffic",
            })

        # Format TI findings
        ti_findings = []
        for ti in ti_list:
            q_ioc = ti.get("queried_ioc", "")
            matches = ti.get("matches", [])
            match_found = ti.get("match_found", False)
            source_name = matches[0].get("source") if matches else "Local MISP"
            interpretation = "Known indicator in threat database" if match_found else "Indicator not found in local threat database; does not imply indicator is benign"
            ti_findings.append({
                "ioc": q_ioc,
                "source": source_name,
                "match_found": match_found,
                "interpretation": interpretation,
            })

        # Format MITRE analysis fallback (all marked PLAUSIBLE or NOT_CONFIRMED)
        mitre_analysis = []
        for m in evidence_package.get("mitre_candidates", []):
            mitre_analysis.append({
                "technique_id": m.get("technique_id", "Unknown"),
                "technique_name": m.get("technique_name", "Unknown"),
                "assessment": "PLAUSIBLE / NEEDS MORE EVIDENCE",
                "reason": "Retrieved as candidate based on behavioral similarity; pending manual analyst confirmation.",
                "evidence": behavioral_ev,
            })

        # Playbook & CISA
        pb_recs = [
            f"{p.get('playbook_name')}: Follow initial triage and containment steps"
            for p in evidence_package.get("playbook_evidence", [])
        ]
        cisa_recs = [
            f"{c.get('document_title')}: Apply relevant CISA defensive guidance"
            for c in evidence_package.get("cisa_evidence", [])
        ]

        return {
            "event_type": alert_meta.get("event_type"),
            "alert_id": alert_meta.get("alert_id"),
            "alert_summary": f"Incident alert {alert_meta.get('alert_id', 'Unknown')}: {alert_meta.get('event_type', 'Security Incident')} detected.",
            "incident_assessment": classified_error["user_assessment"],
            "severity_assessment": {
                "alert_severity": alert_meta.get("severity", "UNKNOWN"),
                "assessed_severity": alert_meta.get("severity", "UNKNOWN"),
                "justification": "Original alert severity retained pending analyst verification due to AI reasoning layer unavailability.",
            },
            "behavioral_evidence": behavioral_ev,
            "ioc_findings": ioc_findings,
            "threat_intelligence_findings": ti_findings,
            "mitre_analysis": mitre_analysis,
            "playbook_recommendations": pb_recs,
            "cisa_guidance": cisa_recs,
            "recommended_actions": [
                "Review evidence package manually.",
                "Validate source IP against organizational firewall logs.",
                "Execute recommended initial containment steps from playbook.",
            ],
            "analyst_review_required": True,
            "limitations": [
                classified_error["limitation"],
                "Automated MITRE confirmation could not be generated by LLM.",
            ],
        }

    def reason_over_evidence(
        self,
        evidence_package: Dict[str, Any],
    ) -> Dict[str, Any]:
        """
        Execute evidence-grounded reasoning over the Evidence Package.
        Returns the final structured Incident Triage Report.
        """
        if not isinstance(evidence_package, dict):
            raise TypeError("evidence_package must be a dictionary.")

        # Check client availability
        client = self._initialize_client()
        if client is None:
            return self.generate_fallback_report(
                evidence_package,
                error_message="Gemini client could not be initialized or GOOGLE_API_KEY is not set.",
            )

        prompt = self.build_prompt(evidence_package)

        try:
            response = client.invoke(prompt)
            content = response.content if hasattr(response, "content") else str(response)

            # Handle list of blocks if returned
            if isinstance(content, list):
                text_parts = []
                for b in content:
                    if isinstance(b, dict) and "text" in b:
                        text_parts.append(b["text"])
                    elif isinstance(b, str):
                        text_parts.append(b)
                content = " ".join(text_parts)

            cleaned_json = clean_json_response(content)
            parsed_report = json.loads(cleaned_json)

            # Enforce safety defaults
            if not isinstance(parsed_report, dict):
                return self.generate_fallback_report(
                    evidence_package,
                    error_message="LLM response did not produce a valid JSON dictionary.",
                )

            # Ensure analyst_review_required is unconditionally True
            parsed_report["analyst_review_required"] = True

            return parsed_report

        except Exception as e:
            # Safely classify error without leaking raw stack trace or secrets
            classified = classify_gemini_error(e, secret_key=self.active_secret_key)
            logger.warning(
                "Gemini API invocation failed [%s - %s]: %s",
                classified["code"],
                classified["category"],
                classified["technical_detail"],
            )
            return self.generate_fallback_report(
                evidence_package,
                classified_error=classified,
            )

    def ask_question_over_incident(
        self,
        triage_report: Dict[str, Any],
        question: str,
        alert_text: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        Answer an analyst question strictly grounded in the analyzed incident.
        Never fabricates evidence or invents findings.
        Returns structured answer with distinct categories:
        - Incident Evidence
        - RAG Evidence
        - AI Interpretation
        - Uncertainty
        - Analyst Review
        """
        if not isinstance(triage_report, dict):
            raise TypeError("triage_report must be a dictionary.")

        q_clean = question.strip() if question else ""
        if not q_clean:
            raise ValueError("question must not be empty.")

        # Prepare sanitized grounding context
        alert_summary = triage_report.get("alert_summary", "Not available")
        incident_assessment = triage_report.get("incident_assessment", "Not available")
        sev = triage_report.get("severity_assessment", {})
        behavioral_ev = triage_report.get("behavioral_evidence", [])
        iocs = triage_report.get("ioc_findings", [])
        ti_findings = triage_report.get("threat_intelligence_findings", [])
        mitre = triage_report.get("mitre_analysis", [])
        playbooks = triage_report.get("playbook_recommendations", [])
        cisa = triage_report.get("cisa_guidance", [])
        actions = triage_report.get("recommended_actions", [])
        limitations = triage_report.get("limitations", [])

        # Build deterministic fallback response
        def _deterministic_answer() -> str:
            q_lower = q_clean.lower()
            sections = []

            # 1. Incident Evidence
            if any(k in q_lower for k in ["ioc", "ip", "hash", "domain", "url"]):
                ioc_desc = ", ".join([f"{item.get('ioc')} ({item.get('context', 'network')})" for item in iocs]) if iocs else "No specific IOCs extracted."
                sections.append(f"**Incident Evidence**:\n- Extracted IOCs: {ioc_desc}")
            else:
                b_desc = "\n".join([f"- {b}" for b in behavioral_ev]) if behavioral_ev else "- No behavioral evidence recorded."
                sections.append(f"**Incident Evidence**:\n{b_desc}")

            # 2. RAG Evidence
            if any(k in q_lower for k in ["mitre", "technique", "attack", "t1"]):
                mitre_lines = [
                    f"- {m.get('technique_id')} ({m.get('technique_name')}): {m.get('assessment')} — {m.get('reason')}"
                    for m in mitre
                ]
                rag_text = "\n".join(mitre_lines) if mitre_lines else "- No MITRE techniques retrieved."
                sections.append(f"**RAG Evidence (MITRE ATT&CK)**:\n{rag_text}")
            elif any(k in q_lower for k in ["playbook", "cisa", "guidance", "procedure", "remediat"]):
                pb_text = "\n".join([f"- {p}" for p in playbooks]) if playbooks else "- No specific playbook retrieved."
                cisa_text = "\n".join([f"- {c}" for c in cisa[:3]]) if cisa else "- No CISA guidance retrieved."
                sections.append(f"**RAG Evidence (Playbooks & CISA)**:\n{pb_text}\n{cisa_text}")
            elif any(k in q_lower for k in ["threat", "intel", "misp", "abuse"]):
                ti_lines = [
                    f"- {t.get('ioc')}: {'MATCH FOUND' if t.get('match_found') else 'No match in queried DB'} ({t.get('interpretation')})"
                    for t in ti_findings
                ]
                ti_text = "\n".join(ti_lines) if ti_lines else "- No threat intelligence findings recorded."
                sections.append(f"**RAG Evidence (Threat Intelligence)**:\n{ti_text}")
            else:
                mitre_brief = ", ".join([f"{m.get('technique_id')} ({m.get('assessment')})" for m in mitre[:3]])
                sections.append(f"**RAG Evidence**:\n- Evaluated Techniques: {mitre_brief or 'None'}\n- Playbook: {playbooks[0] if playbooks else 'Standard Incident Triage'}")

            # 3. AI Interpretation
            if any(k in q_lower for k in ["why", "severity", "classif", "assess"]):
                sections.append(f"**AI Interpretation**:\n- Severity: {sev.get('assessed_severity', 'Unknown')} (Original alert: {sev.get('alert_severity', 'Unknown')})\n- Justification: {sev.get('justification', incident_assessment)}")
            else:
                sections.append(f"**AI Interpretation**:\n- Current Assessment: {incident_assessment}")

            # 4. Uncertainty
            lim_text = "\n".join([f"- {lim}" for lim in limitations]) if limitations else "- Evidence is limited strictly to ingested alert attributes."
            sections.append(f"**Uncertainty**:\n{lim_text}")

            # 5. Analyst Review
            rec_text = "\n".join([f"- {act}" for act in actions[:3]]) if actions else "- Validate evidence package manually."
            sections.append(f"**Analyst Review Required**:\n{rec_text}\n- Human analyst review is required before taking containment actions.")

            return "\n\n".join(sections)

        # Attempt Gemini invocation if client is ready
        client = self._initialize_client()
        if client is not None:
            qa_prompt = f"""You are a disciplined SOC Incident Triage AI Assistant.
Answer the analyst question ONLY using the factual Incident Triage Report below.
Do not hallucinate or invent IOCs, tools, or attacker actions.
If the report does not provide the information needed to answer the question, explicitly state:
"The available incident evidence does not establish this."

You MUST organize your response into these 5 labeled sections:
- **Incident Evidence**
- **RAG Evidence**
- **AI Interpretation**
- **Uncertainty**
- **Analyst Review**

INCIDENT REPORT CONTEXT:
Alert Summary: {alert_summary}
Incident Assessment: {incident_assessment}
Severity Assessment: {json.dumps(sev)}
Behavioral Evidence: {json.dumps(behavioral_ev)}
IOC Findings: {json.dumps(iocs)}
Threat Intelligence: {json.dumps(ti_findings)}
MITRE Analysis: {json.dumps(mitre)}
Playbook Recommendations: {json.dumps(playbooks)}
CISA Guidance: {json.dumps(cisa)}
Recommended Actions: {json.dumps(actions)}
Limitations: {json.dumps(limitations)}

ANALYST QUESTION:
{q_clean}"""
            try:
                resp = client.invoke(qa_prompt)
                ans_text = resp.content if hasattr(resp, "content") else str(resp)
                if isinstance(ans_text, list):
                    ans_text = " ".join([b.get("text", "") if isinstance(b, dict) else str(b) for b in ans_text])
                if ans_text and ans_text.strip() and ans_text.strip() != "{}":
                    return {
                        "question": q_clean,
                        "answer": ans_text.strip(),
                        "grounding": {
                            "source": "Gemini Grounded Reasoning",
                            "behavioral_evidence_count": len(behavioral_ev),
                            "ioc_count": len(iocs),
                            "mitre_count": len(mitre),
                        },
                    }
            except Exception as e:
                classified = classify_gemini_error(e, secret_key=self.active_secret_key)
                logger.warning(
                    "Gemini Q&A invocation failed [%s]: %s",
                    classified["code"],
                    classified["technical_detail"],
                )

        # Fallback to deterministic grounded answer
        return {
            "question": q_clean,
            "answer": _deterministic_answer(),
            "grounding": {
                "source": "Deterministic Report Grounding",
                "behavioral_evidence_count": len(behavioral_ev),
                "ioc_count": len(iocs),
                "mitre_count": len(mitre),
            },
        }
