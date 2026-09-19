# Cybersecurity Incident Triage AI — Backend Service

A high-assurance, evidence-grounded cybersecurity incident-triage REST API built with FastAPI, multi-source Retrieval-Augmented Generation (RAG), live threat intelligence enrichment, and Google Gemini.

---

## Overview & Purpose

Modern Security Operations Centers (SOCs) are inundated with alerts requiring rapid triage, attribution, and procedural guidance. **Cybersecurity Incident Triage AI** automates this process without speculative guesswork or black-box decision making.

The system enforces a **strictly evidence-first architecture**:
1. **Deterministic Alert Parsing**: Ingests raw security alerts and extracts metadata, network context, behavioral evidence, and observable IOCs using deterministic pattern matching.
2. **Multi-Source RAG Retrieval**: Simultaneously queries semantic vector indices for MITRE ATT&CK techniques, standardized response playbooks, and CISA cybersecurity guidance.
3. **Threat Intelligence Enrichment**: Correlates observables against local threat databases and live open-source abuse feeds (ThreatFox, URLhaus, MalwareBazaar).
4. **Structured Evidence Package Assembly**: Unifies all verified facts, retrieved knowledge, and threat telemetry into an immutable evidence package.
5. **Grounded AI Triage Synthesis**: Uses Google Gemini to generate advisory classifications, technique justifications, and recommended actions strictly bounded by the evidence package.
6. **Analyst-in-the-Loop Verification**: Flags analyst review requirements to ensure human oversight before executing containment or remediation.

---

## System Architecture

```
                       +-------------------------+
                       | Raw Alert / SIEM Payload |
                       +------------+------------+
                                    |
                                    v
                       +-------------------------+
                       |   Deterministic Parser  |
                       |  (Regex & Field Normal) |
                       +------------+------------+
                                    |
            +-----------------------+-----------------------+
            |                       |                       |
            v                       v                       v
+-----------------------+ +--------------------+ +--------------------+
|  MITRE ATT&CK Vector  | | Playbooks Vector   | |  CISA Guidance     |
|  Store (FAISS Index)  | | Store (FAISS Index)| | Vector Store (FAISS|
+-----------+-----------+ +---------+----------+ +---------+----------+
            |                       |                      |
            +-----------------------+----------------------+
                                    |
                                    v
                       +-------------------------+
                       |    Threat Intelligence  |
                       | (Local Cache + Live API)|
                       +------------+------------+
                                    |
                                    v
                       +-------------------------+
                       | Structured Evidence Pkg |
                       +------------+------------+
                                    |
                                    v
                       +-------------------------+
                       |   Gemini Triage Engine  |
                       |  (Bounded Synthesis)    |
                       +------------+------------+
                                    |
                                    v
                       +-------------------------+
                       | Structured Triage Report|
                       |  (Advisory SOC Output)  |
                       +-------------------------+
```

---

## Knowledge Sources & RAG Subsystems

The RAG orchestrator (`src/rag/multi_source_retriever.py`) manages three specialized vector stores:

### 1. MITRE ATT&CK (`src/rag/mitre_retriever.py`)
- **Coverage**: 1,488 indexed enterprise technique vectors.
- **Embedding Model**: `sentence-transformers/all-MiniLM-L6-v2`.
- **Purpose**: Maps extracted behavioral observables to candidate technique IDs (e.g., T1059.001) and assesses them as `Supported`, `Plausible`, or `Not Supported`.

### 2. Response Playbooks (`src/rag/playbook_retriever.py`)
- **Coverage**: Standardized incident response playbooks for brute force, credential compromise, malware infection, phishing, suspicious IP activity, and suspicious PowerShell executions.
- **Lifecycle Stages**: Initial Triage, Investigation, Containment, Eradication, Recovery, Evidence Collection, Escalation Criteria, and Closure Criteria.

### 3. CISA Guidance (`src/rag/cisa_retriever.py`)
- **Coverage**: Federal cybersecurity advisories, ransomware response checklists, telemetry logging standards, and network visibility benchmarks.
- **Purpose**: Correlates incidents against national hardening standards and authoritative mitigation advice.

---

## Threat Intelligence Integration (`src/tools/`)

- **Observable Support**: IPv4/IPv6 addresses, domains, URLs, and file hashes (MD5, SHA-1, SHA-256).
- **Local Cache**: Instant offline lookups against known threat indices.
- **Live Feeds via Abuse.ch**:
  - **ThreatFox**: Real-time malware indicator sharing and IP/domain associations.
  - **URLhaus**: Malicious URL detection and payload distribution tracking.
  - **MalwareBazaar**: Malware sample identification and signature verification.
- **Fail-Safe Operation**: Unreachable external threat feeds fall back to local data gracefully without interrupting alert triage.

---

## Project Structure

```
.
├── data/                       # FAISS vector stores, chunks, and metadata
│   ├── rag/cisa/               # CISA vector store and chunk files
│   ├── rag/mitre/              # MITRE ATT&CK vector store and chunk files
│   └── rag/playbooks/          # Response playbook markdown and vector indices
├── notebooks/                  # Dataset preparation and validation scripts
├── src/
│   ├── agent/                  # TriageAgent & GeminiTriageEngine
│   ├── api/                    # FastAPI routes, schemas, and dependencies
│   ├── nlp/                    # Deterministic alert parser and regex rules
│   ├── rag/                    # Multi-source retrievers and evidence builder
│   └── tools/                  # Threat intelligence and live Abuse.ch tools
├── .env.example                # Environment template (no secrets)
├── .gitignore                  # Git ignore rules for secrets, DBs, and frontend
├── README.md                   # This documentation
└── requirements.txt            # Python runtime dependencies
```

---

## REST API Endpoints

| Method | Endpoint | Description |
| :--- | :--- | :--- |
| `GET` | `/` | Root service metadata and operating status. |
| `GET` | `/health` | Operational health probe for load balancers and console probes. |
| `POST` | `/api/v1/triage` | Ingests a raw security alert and returns the complete triage report. |
| `POST` | `/api/v1/incident/ask` | Interactive Q&A scoped strictly to an analyzed incident's evidence package. |
| `GET` | `/docs` | Interactive Swagger UI / OpenAPI documentation. |

---

## Local Setup & Installation

### Prerequisites
- Python 3.10 to 3.13
- Git

### 1. Clone & Set Up Environment
```bash
git clone https://github.com/your-username/cybersecurity_incident_triage_backend.git
cd cybersecurity_incident_triage_backend

# Create and activate virtual environment
python -m venv venv
# On Windows:
.\venv\Scripts\activate
# On Linux/macOS:
source venv/bin/activate
```

### 2. Install Dependencies
```bash
pip install -r requirements.txt
```

### 3. Configure Environment Variables
Copy `.env.example` to `.env` and provide your credentials:
```bash
cp .env.example .env
```

Edit `.env`:
```ini
GOOGLE_API_KEY=your_google_api_key_here
GEMINI_MODEL=gemini-1.5-flash
ALLOWED_ORIGINS=http://localhost:8080,http://127.0.0.1:8080
```

---

## Running the Application

### Development Server
```bash
python -m uvicorn src.api.main:app --host 127.0.0.1 --port 8000 --reload
```

### Production Execution
```bash
python -m uvicorn src.api.main:app --host 0.0.0.0 --port 8000 --workers 4
```

Once running:
- **API Base**: `http://127.0.0.1:8000`
- **Interactive Documentation**: `http://127.0.0.1:8000/docs`
- **Health Check**: `http://127.0.0.1:8000/health`

---

## Running Tests

Execute the automated test suite across parsing, RAG retrieval, threat intelligence, and API endpoints:

```bash
# Run alert parser tests
python src/nlp/test_alert_parser.py

# Run RAG behavior and vector retrieval tests
python src/rag/test_mitre_behavior.py
python src/rag/test_playbook_behavior.py
python src/rag/test_cisa_behavior.py

# Run threat intelligence tests
python src/tools/test_threat_intel_service.py

# Run full API and triage integration tests
python src/api/test_api.py
```

---

## Security & Ethics Principle

> **Advisory Determination**: AI-generated classifications, MITRE technique assessments, and recommended remediation actions produced by this platform are advisory. Human SOC analysts remain the final authoritative decision-makers before containment or eradication actions are applied.
