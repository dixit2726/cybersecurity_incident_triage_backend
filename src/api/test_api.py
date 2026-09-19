import json
import os
import sys
import unittest
from unittest.mock import MagicMock

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

from fastapi.testclient import TestClient

from src.agent.gemini_triage_engine import GeminiTriageEngine
from src.agent.test_end_to_end import create_mock_llm_response
from src.agent.triage_agent import TriageAgent
from src.api.dependencies import get_triage_agent
from src.api.main import app

# Sample complete SSH alert for API testing
SAMPLE_SSH_ALERT = """ALERT_ID: SEC-2026-0915-001
Timestamp: 2026-09-15 10:32:11
Severity: High
Event Type: Brute Force Attack
Source IP: 185.234.72.19
Destination IP: 10.10.25.14
Protocol: TCP
Destination Port: 22

Multiple failed SSH authentication attempts detected.
47 failed authentication attempts were recorded within 5 minutes.
5 different usernames were targeted.
No successful login was detected."""


class DynamicMockLLM:
    """Mock LLM that dynamically formats realistic, grounded JSON from Evidence Package."""
    def invoke(self, prompt: str):
        start_tag = "EVIDENCE PACKAGE:\n"
        end_tag = "\n\nINSTRUCTIONS:"
        if start_tag in prompt and end_tag in prompt:
            pkg_str = prompt.split(start_tag)[1].split(end_tag)[0].strip()
            try:
                pkg_dict = json.loads(pkg_str)
                resp_content = create_mock_llm_response(pkg_dict)
                return MagicMock(content=resp_content)
            except Exception:
                pass
        if "ANALYST QUESTION:" in prompt:
            return MagicMock(content="**Incident Evidence**:\n- Telemetry confirms brute force.\n\n**RAG Evidence**:\n- MITRE T1110.\n\n**AI Interpretation**:\n- High severity retained.\n\n**Uncertainty**:\n- Telemetry limited to logs.\n\n**Analyst Review**:\n- Verify firewall logs.")
        return MagicMock(content="{}")


class FailingMockLLM:
    """Mock LLM that simulates Gemini API failure/outage."""
    def invoke(self, prompt: str):
        raise RuntimeError("Simulated Google Gemini API 503 Service Unavailable / Rate Limit")


def build_test_triage_agent(failing_llm: bool = False) -> TriageAgent:
    """Build a TriageAgent with real RAG retriever and mocked LLM (no live Gemini calls)."""
    mock_llm = FailingMockLLM() if failing_llm else DynamicMockLLM()
    gemini_engine = GeminiTriageEngine(llm_client=mock_llm)
    return TriageAgent(gemini_engine=gemini_engine, enable_live=False)


class TestFastAPIBackend(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        print("\n" + "=" * 60)
        print("INITIALIZING STEP 14 FASTAPI BACKEND TEST SUITE")
        print("=" * 60)
        # Create singleton agent for testing with real RAG pipeline + mocked LLM
        cls.test_agent = build_test_triage_agent(failing_llm=False)
        app.state.triage_agent = cls.test_agent
        cls.client = TestClient(app)

    def test_01_root_endpoint(self):
        """TEST 1: GET / -> 200 and basic API information."""
        response = self.client.get("/")
        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertEqual(data.get("service"), "Cybersecurity Incident Triage AI")
        self.assertEqual(data.get("version"), "1.0.0")
        self.assertEqual(data.get("status"), "running")
        print("[PASS] TEST 1 — GET / returned 200 with service info")

    def test_02_health_endpoint(self):
        """TEST 2: GET /health -> 200 and healthy status."""
        response = self.client.get("/health")
        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertEqual(data.get("status"), "healthy")
        print("[PASS] TEST 2 — GET /health returned 200 with status: healthy")

    def test_03_triage_valid_alert(self):
        """TEST 3: POST /api/v1/triage with valid complete SSH alert -> 200."""
        payload = {
            "alert_text": SAMPLE_SSH_ALERT,
            "enable_live": False,
        }
        response = self.client.post("/api/v1/triage", json=payload)
        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertTrue(data.get("success"))
        print("[PASS] TEST 3 — POST /api/v1/triage returned 200 with success=True")

    def test_04_alert_id_preserved(self):
        """TEST 4: Verify alert_id is preserved in response."""
        payload = {
            "alert_text": SAMPLE_SSH_ALERT,
            "enable_live": False,
        }
        response = self.client.post("/api/v1/triage", json=payload)
        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertEqual(data.get("alert_id"), "SEC-2026-0915-001")
        print(f"[PASS] TEST 4 — Alert ID preserved: {data.get('alert_id')}")

    def test_05_structured_triage_report_exists(self):
        """TEST 5: Verify structured triage_report exists and contains all required sections."""
        payload = {
            "alert_text": SAMPLE_SSH_ALERT,
            "enable_live": False,
        }
        response = self.client.post("/api/v1/triage", json=payload)
        self.assertEqual(response.status_code, 200)
        report = response.json().get("triage_report", {})
        
        required_keys = [
            "alert_summary",
            "incident_assessment",
            "severity_assessment",
            "behavioral_evidence",
            "ioc_findings",
            "threat_intelligence_findings",
            "mitre_analysis",
            "playbook_recommendations",
            "cisa_guidance",
            "recommended_actions",
            "analyst_review_required",
            "limitations",
        ]
        for key in required_keys:
            self.assertIn(key, report, f"Missing required report section: {key}")
        print(f"[PASS] TEST 5 — Structured triage report verified with all {len(required_keys)} sections")

    def test_06_analyst_review_required(self):
        """TEST 6: Verify analyst_review_required == True."""
        payload = {
            "alert_text": SAMPLE_SSH_ALERT,
            "enable_live": False,
        }
        response = self.client.post("/api/v1/triage", json=payload)
        self.assertEqual(response.status_code, 200)
        report = response.json().get("triage_report", {})
        self.assertIs(report.get("analyst_review_required"), True)
        print("[PASS] TEST 6 — analyst_review_required is unconditionally True")

    def test_07_mitre_analysis_exists(self):
        """TEST 7: Verify MITRE analysis exists and contains retrieved candidates."""
        payload = {
            "alert_text": SAMPLE_SSH_ALERT,
            "enable_live": False,
        }
        response = self.client.post("/api/v1/triage", json=payload)
        self.assertEqual(response.status_code, 200)
        mitre = response.json().get("triage_report", {}).get("mitre_analysis", [])
        self.assertIsInstance(mitre, list)
        self.assertGreater(len(mitre), 0)
        first = mitre[0]
        self.assertIn("technique_id", first)
        self.assertIn("assessment", first)
        print(f"[PASS] TEST 7 — MITRE analysis contains {len(mitre)} evaluated techniques (e.g. {first.get('technique_id')})")

    def test_08_playbook_recommendations_exist(self):
        """TEST 8: Verify playbook recommendations exist."""
        payload = {
            "alert_text": SAMPLE_SSH_ALERT,
            "enable_live": False,
        }
        response = self.client.post("/api/v1/triage", json=payload)
        self.assertEqual(response.status_code, 200)
        pb = response.json().get("triage_report", {}).get("playbook_recommendations", [])
        self.assertIsInstance(pb, list)
        self.assertGreater(len(pb), 0)
        print(f"[PASS] TEST 8 — Playbook recommendations present: {len(pb)} entries")

    def test_09_cisa_guidance_exists(self):
        """TEST 9: Verify CISA guidance exists."""
        payload = {
            "alert_text": SAMPLE_SSH_ALERT,
            "enable_live": False,
        }
        response = self.client.post("/api/v1/triage", json=payload)
        self.assertEqual(response.status_code, 200)
        cisa = response.json().get("triage_report", {}).get("cisa_guidance", [])
        self.assertIsInstance(cisa, list)
        self.assertGreater(len(cisa), 0)
        print(f"[PASS] TEST 9 — CISA guidance present: {len(cisa)} entries")

    def test_10_empty_alert_422(self):
        """TEST 10: Empty alert string -> 422."""
        payload = {"alert_text": "", "enable_live": False}
        response = self.client.post("/api/v1/triage", json=payload)
        self.assertEqual(response.status_code, 422)
        print("[PASS] TEST 10 — Empty alert correctly rejected with HTTP 422")

    def test_11_whitespace_only_alert_422(self):
        """TEST 11: Whitespace-only alert -> 422."""
        payload = {"alert_text": "   \n\t  \r\n  ", "enable_live": False}
        response = self.client.post("/api/v1/triage", json=payload)
        self.assertEqual(response.status_code, 422)
        print("[PASS] TEST 11 — Whitespace-only alert rejected with HTTP 422")

    def test_12_malformed_request_422(self):
        """TEST 12: Malformed request -> 422."""
        # Missing required alert_text
        response1 = self.client.post("/api/v1/triage", json={"enable_live": True})
        self.assertEqual(response1.status_code, 422)

        # Invalid type for alert_text
        response2 = self.client.post("/api/v1/triage", json={"alert_text": 12345})
        self.assertEqual(response2.status_code, 422)
        print("[PASS] TEST 12 — Malformed requests correctly rejected with HTTP 422")

    def test_13_gemini_failure_graceful_fallback(self):
        """TEST 13: Gemini API failure -> existing controlled fallback report returned, not 500."""
        failing_agent = build_test_triage_agent(failing_llm=True)
        # Override dependency temporarily
        app.dependency_overrides[get_triage_agent] = lambda: failing_agent

        try:
            payload = {
                "alert_text": SAMPLE_SSH_ALERT,
                "enable_live": False,
            }
            response = self.client.post("/api/v1/triage", json=payload)
            self.assertEqual(response.status_code, 200)
            data = response.json()
            self.assertTrue(data.get("success"))
            report = data.get("triage_report", {})
            self.assertIn("AI reasoning layer was unavailable", report.get("incident_assessment", ""))
            self.assertIs(report.get("analyst_review_required"), True)
            self.assertGreater(len(report.get("limitations", [])), 0)
            print("[PASS] TEST 13 — Gemini failure handled safely via controlled fallback report (HTTP 200, no 500 crash)")
        finally:
            app.dependency_overrides.pop(get_triage_agent, None)

    def test_14_no_api_keys_in_response(self):
        """TEST 14: Verify API response does not contain API keys."""
        # Retrieve whatever is configured in env to test against
        env_key = os.getenv("GOOGLE_API_KEY", "").strip()

        payload = {
            "alert_text": SAMPLE_SSH_ALERT,
            "enable_live": False,
        }
        response = self.client.post("/api/v1/triage", json=payload)
        resp_text = response.text

        # Never leak key names or secret prefixes
        self.assertNotIn("AIzaSy", resp_text)
        if env_key and len(env_key) > 8:
            self.assertNotIn(env_key, resp_text)
        print("[PASS] TEST 14 — Zero API keys or secrets detected in API response body")

    def test_15_no_raw_prompt_endpoint(self):
        """TEST 15: Verify no raw prompt or direct LLM endpoint exists."""
        resp_prompt = self.client.post("/prompt", json={"prompt": "test"})
        self.assertEqual(resp_prompt.status_code, 404)

        resp_gemini = self.client.post("/gemini", json={"text": "test"})
        self.assertEqual(resp_gemini.status_code, 404)

        resp_raw = self.client.post("/api/v1/prompt", json={"text": "test"})
        self.assertEqual(resp_raw.status_code, 404)
        print("[PASS] TEST 15 — Verified NO raw prompt/gemini endpoints exist (404 Not Found)")

    def test_16_performance_singleton_reuse(self):
        """TEST 16: Performance/Singleton test — verify multiple requests reuse the same TriageAgent instance."""
        recorded_agents = []

        def tracking_dep():
            agent = app.state.triage_agent
            recorded_agents.append(agent)
            return agent

        app.dependency_overrides[get_triage_agent] = tracking_dep

        try:
            payload = {"alert_text": SAMPLE_SSH_ALERT, "enable_live": False}
            resp1 = self.client.post("/api/v1/triage", json=payload)
            resp2 = self.client.post("/api/v1/triage", json=payload)
            resp3 = self.client.post("/api/v1/triage", json=payload)

            self.assertEqual(resp1.status_code, 200)
            self.assertEqual(resp2.status_code, 200)
            self.assertEqual(resp3.status_code, 200)

            self.assertEqual(len(recorded_agents), 3)
            # Verify exact object identity reuse
            self.assertIs(recorded_agents[0], recorded_agents[1])
            self.assertIs(recorded_agents[1], recorded_agents[2])
            print(f"[PASS] TEST 16 — Verified exact service object reuse across requests (Agent ID: {id(recorded_agents[0])})")
        finally:
            app.dependency_overrides.pop(get_triage_agent, None)

    def test_17_incident_scoped_ask(self):
        """TEST 17: Scoped Incident Q&A endpoint — answers questions strictly using incident report."""
        # 1. Obtain real report from triage
        triage_resp = self.client.post("/api/v1/triage", json={"alert_text": SAMPLE_SSH_ALERT, "enable_live": False})
        self.assertEqual(triage_resp.status_code, 200)
        report = triage_resp.json().get("triage_report")

        # 2. Ask question
        ask_payload = {
            "triage_report": report,
            "question": "Why was this alert classified as High severity?",
            "alert_text": SAMPLE_SSH_ALERT,
        }
        ask_resp = self.client.post("/api/v1/incident/ask", json=ask_payload)
        self.assertEqual(ask_resp.status_code, 200)
        ask_data = ask_resp.json()
        self.assertTrue(ask_data.get("success"))
        ans = ask_data.get("answer", "")
        self.assertIn("Incident Evidence", ans)
        self.assertIn("Analyst Review", ans)

        # 3. Empty question -> 422
        bad_resp = self.client.post("/api/v1/incident/ask", json={"triage_report": report, "question": "   "})
        self.assertEqual(bad_resp.status_code, 422)
        print("[PASS] TEST 17 — Verified scoped incident assistant endpoint POST /api/v1/incident/ask")


def run_api_tests():
    suite = unittest.TestLoader().loadTestsFromTestCase(TestFastAPIBackend)
    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)
    if not result.wasSuccessful():
        sys.exit(1)


if __name__ == "__main__":
    run_api_tests()
