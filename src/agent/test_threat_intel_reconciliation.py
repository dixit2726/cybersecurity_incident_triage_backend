import unittest
from src.agent.gemini_triage_engine import GeminiTriageEngine


class TestThreatIntelReconciliation(unittest.TestCase):
    """
    Regression test suite ensuring Threat Intelligence lookup results are treated
    as authoritative deterministic evidence and cannot be overridden by LLM hallucination.
    """

    def setUp(self):
        self.engine = GeminiTriageEngine(api_key="mock_key")

    def test_01_positive_hash_match_fields(self):
        """
        Test 1:
        Positive hash match remains:
        match_found = true
        source = MalwareBazaar
        ioc_type = md5_hash
        threat_type = malware_sample
        """
        evidence_package = {
            "threat_intelligence": [
                {
                    "queried_ioc": "3da81722c72b21f29acaa873341da517",
                    "ioc_type": "hash",
                    "match_found": True,
                    "matches": [
                        {
                            "ioc": "3da81722c72b21f29acaa873341da517",
                            "ioc_type": "md5_hash",
                            "source": "MalwareBazaar",
                            "threat_type": "malware_sample",
                            "malware": "",
                            "confidence": "",
                            "tags": "",
                            "reference": "",
                        }
                    ],
                }
            ]
        }
        llm_report = {
            "threat_intelligence_findings": [
                {
                    "ioc": "3da81722c72b21f29acaa873341da517",
                    "match_found": True,
                    "source": "MalwareBazaar",
                    "interpretation": "Observed in threat intelligence feed.",
                }
            ]
        }

        reconciled = self.engine.reconcile_threat_intelligence(llm_report, evidence_package)
        f0 = reconciled["threat_intelligence_findings"][0]

        self.assertEqual(f0["match_found"], True)
        self.assertEqual(f0["source"], "MalwareBazaar")
        self.assertEqual(f0["ioc_type"], "md5_hash")
        self.assertEqual(f0["threat_type"], "malware_sample")

    def test_02_llm_cannot_change_true_to_false(self):
        """
        Test 2:
        LLM cannot change true -> false.
        """
        evidence_package = {
            "threat_intelligence": [
                {
                    "queried_ioc": "3da81722c72b21f29acaa873341da517",
                    "ioc_type": "hash",
                    "match_found": True,
                    "matches": [
                        {
                            "ioc": "3da81722c72b21f29acaa873341da517",
                            "ioc_type": "md5_hash",
                            "source": "MalwareBazaar",
                            "threat_type": "malware_sample",
                        }
                    ],
                }
            ]
        }
        # Simulated LLM hallucination changing match_found to False
        llm_report = {
            "threat_intelligence_findings": [
                {
                    "ioc": "3da81722c72b21f29acaa873341da517",
                    "source": "Local/Queried Dataset",
                    "match_found": False,
                    "interpretation": "The file hash was not found in the local/queried dataset; this does not confirm the file is safe.",
                }
            ]
        }

        reconciled = self.engine.reconcile_threat_intelligence(llm_report, evidence_package)
        f0 = reconciled["threat_intelligence_findings"][0]

        self.assertTrue(f0["match_found"], "LLM must NOT be permitted to change match_found from True to False")
        self.assertEqual(f0["source"], "MalwareBazaar")

    def test_03_llm_cannot_change_false_to_true(self):
        """
        Test 3:
        LLM cannot change false -> true.
        """
        evidence_package = {
            "threat_intelligence": [
                {
                    "queried_ioc": "198.51.100.25",
                    "ioc_type": "ip",
                    "match_found": False,
                    "matches": [],
                }
            ]
        }
        # Simulated LLM hallucination claiming match_found is True
        llm_report = {
            "threat_intelligence_findings": [
                {
                    "ioc": "198.51.100.25",
                    "source": "ThreatFox",
                    "match_found": True,
                    "interpretation": "Found as known C2 server in threat feeds.",
                }
            ]
        }

        reconciled = self.engine.reconcile_threat_intelligence(llm_report, evidence_package)
        f0 = reconciled["threat_intelligence_findings"][0]

        self.assertFalse(f0["match_found"], "LLM must NOT be permitted to change match_found from False to True")
        self.assertEqual(f0["source"], "Local Threat Intelligence Database")

    def test_04_multiple_iocs_remain_correctly_reconciled(self):
        """
        Test 4:
        Multiple IOCs remain correctly reconciled.
        """
        evidence_package = {
            "threat_intelligence": [
                {
                    "queried_ioc": "185.234.72.19",
                    "ioc_type": "ip",
                    "match_found": False,
                    "matches": [],
                },
                {
                    "queried_ioc": "10.10.25.14",
                    "ioc_type": "ip",
                    "match_found": False,
                    "matches": [],
                },
                {
                    "queried_ioc": "3da81722c72b21f29acaa873341da517",
                    "ioc_type": "hash",
                    "match_found": True,
                    "matches": [
                        {
                            "ioc": "3da81722c72b21f29acaa873341da517",
                            "ioc_type": "md5_hash",
                            "source": "MalwareBazaar",
                            "threat_type": "malware_sample",
                        }
                    ],
                },
            ]
        }
        llm_report = {
            "threat_intelligence_findings": [
                {
                    "ioc": "185.234.72.19",
                    "match_found": False,
                    "interpretation": "The indicator was not found in the local/queried dataset; this does not mean the indicator is benign.",
                },
                {
                    "ioc": "10.10.25.14",
                    "match_found": False,
                    "interpretation": "Internal host.",
                },
                {
                    "ioc": "3da81722c72b21f29acaa873341da517",
                    "match_found": False,  # Hallucinated False
                    "interpretation": "Not found in dataset.",
                },
            ]
        }

        reconciled = self.engine.reconcile_threat_intelligence(llm_report, evidence_package)
        findings = reconciled["threat_intelligence_findings"]
        self.assertEqual(len(findings), 3)

        by_ioc = {f["ioc"]: f for f in findings}
        self.assertFalse(by_ioc["185.234.72.19"]["match_found"])
        self.assertFalse(by_ioc["10.10.25.14"]["match_found"])
        self.assertIn("RFC 1918", by_ioc["10.10.25.14"]["interpretation"])
        self.assertTrue(by_ioc["3da81722c72b21f29acaa873341da517"]["match_found"])
        self.assertEqual(by_ioc["3da81722c72b21f29acaa873341da517"]["source"], "MalwareBazaar")

    def test_05_positive_match_interpretation_evidence_grounded(self):
        """
        Test 5:
        Positive-match interpretation uses evidence-grounded language and does NOT contain:
        'validates the malicious nature of the executed file'
        """
        evidence_package = {
            "threat_intelligence": [
                {
                    "queried_ioc": "3da81722c72b21f29acaa873341da517",
                    "ioc_type": "hash",
                    "match_found": True,
                    "matches": [
                        {
                            "ioc": "3da81722c72b21f29acaa873341da517",
                            "ioc_type": "md5_hash",
                            "source": "MalwareBazaar",
                            "threat_type": "malware_sample",
                        }
                    ],
                }
            ]
        }
        # LLM response containing overly strong wording
        llm_report = {
            "threat_intelligence_findings": [
                {
                    "ioc": "3da81722c72b21f29acaa873341da517",
                    "source": "MalwareBazaar",
                    "match_found": True,
                    "interpretation": "Confirmed match as a malware sample in MalwareBazaar; validates the malicious nature of the executed file.",
                }
            ]
        }

        reconciled = self.engine.reconcile_threat_intelligence(llm_report, evidence_package)
        interp = reconciled["threat_intelligence_findings"][0]["interpretation"]

        # MUST NOT contain overly strong wording
        self.assertNotIn("validates the malicious nature of the executed file", interp)
        self.assertNotIn("validates the malicious nature", interp)

        # MUST contain evidence-grounded phrasing
        self.assertIn("The hash matches a malware sample listed in MalwareBazaar", interp)
        self.assertIn("analyst review is required to correlate it with the observed execution", interp)

    def test_06_full_triage_report_structure_remains_unchanged(self):
        """
        Test 6:
        The full triage report structure remains unchanged.
        """
        evidence_package = {
            "threat_intelligence": [
                {
                    "queried_ioc": "185.234.72.19",
                    "ioc_type": "ip",
                    "match_found": False,
                    "matches": [],
                }
            ]
        }
        llm_report = {
            "alert_summary": "Brute force attack detected on host 10.10.25.14.",
            "incident_assessment": "Telemetry confirms failed SSH authentications.",
            "severity_assessment": {
                "alert_severity": "High",
                "assessed_severity": "MEDIUM",
                "justification": "Mitigated by lack of success.",
            },
            "behavioral_evidence": ["47 failed login attempts"],
            "ioc_findings": [{"ioc": "185.234.72.19", "type": "ip", "context": "attacker"}],
            "threat_intelligence_findings": [],
            "mitre_analysis": [{"technique_id": "T1110", "assessment": "SUPPORTED"}],
            "playbook_recommendations": ["Block IP"],
            "cisa_guidance": ["Adopt MFA"],
            "recommended_actions": ["Isolate host"],
            "analyst_review_required": True,
            "limitations": ["No PCAP"],
        }

        reconciled = self.engine.reconcile_threat_intelligence(llm_report, evidence_package)

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
        for k in required_keys:
            self.assertIn(k, reconciled)

        self.assertEqual(len(reconciled["threat_intelligence_findings"]), 1)


if __name__ == "__main__":
    unittest.main()
