import unittest
from unittest.mock import MagicMock
from src.db.incident_repository import IncidentRepository


class TestIncidentRepository(unittest.TestCase):
    def setUp(self):
        self.sample_triage_report = {
            "alert_id": "SEC-2026-0915-001",
            "event_type": "Brute Force Attack",
            "severity_assessment": {
                "alert_severity": "High",
                "assessed_severity": "MEDIUM",
                "justification": "Mitigated by lack of success.",
            },
            "ioc_findings": [
                {"ioc": "185.234.72.19", "type": "ip", "context": "external source attacker"},
                {"ioc": "10.10.25.14", "type": "ip", "context": "internal destination target"},
            ],
            "threat_intelligence_findings": [],
            "mitre_analysis": [{"technique_id": "T1110", "assessment": "SUPPORTED"}],
            "playbook_recommendations": ["Block IP on firewall"],
            "cisa_guidance": ["Enforce MFA"],
            "analyst_review_required": True,
        }

    def test_unconfigured_client_graceful_handling(self):
        """When Supabase client is None, operations return None or [] safely without raising."""
        repo = IncidentRepository(client=None)
        res = repo.create_incident("alert text", self.sample_triage_report)
        self.assertIsNone(res)

        get_res = repo.get_incident("any-id")
        self.assertIsNone(get_res)

        list_res = repo.list_incidents()
        self.assertEqual(list_res, [])

        count_res = repo.count_incidents()
        self.assertEqual(count_res, 0)

    def test_create_incident_success(self):
        """Successfully insert an incident via mocked Supabase client."""
        mock_client = MagicMock()
        mock_insert = MagicMock()
        mock_insert.execute.return_value = MagicMock(
            data=[{"id": "a0eebc99-9c0b-4ef8-bb6d-6bb9bd380a11", "incident_id": "SEC-2026-0915-001"}]
        )
        mock_client.table.return_value.insert.return_value = mock_insert

        repo = IncidentRepository(client=mock_client)
        net_ctx = {"source_ip": "185.234.72.19", "destination_ip": "10.10.25.14", "protocol": "TCP", "destination_port": 22}
        result = repo.create_incident(
            alert_text="Raw alert text",
            triage_report=self.sample_triage_report,
            alert_id="SEC-2026-0915-001",
            network_context=net_ctx,
        )

        self.assertIsNotNone(result)
        self.assertEqual(result["id"], "a0eebc99-9c0b-4ef8-bb6d-6bb9bd380a11")
        mock_client.table.assert_called_with("incidents")

    def test_create_incident_exception_handling(self):
        """If Supabase client throws an exception, create_incident returns None without raising."""
        mock_client = MagicMock()
        mock_client.table.side_effect = RuntimeError("Connection timeout to Supabase")

        repo = IncidentRepository(client=mock_client)
        result = repo.create_incident("alert text", self.sample_triage_report)
        self.assertIsNone(result)

    def test_get_incident_by_incident_id(self):
        """Retrieve an incident record by human-readable incident_id."""
        mock_client = MagicMock()
        mock_query = MagicMock()
        mock_query.execute.return_value = MagicMock(
            data=[{"id": "uuid-123", "incident_id": "SEC-2026-0915-001", "severity": "MEDIUM"}]
        )
        mock_client.table.return_value.select.return_value.eq.return_value.order.return_value.limit.return_value = mock_query

        repo = IncidentRepository(client=mock_client)
        record = repo.get_incident("SEC-2026-0915-001")
        self.assertIsNotNone(record)
        self.assertEqual(record["incident_id"], "SEC-2026-0915-001")

    def test_list_incidents_pagination(self):
        """List incidents with limit and offset range."""
        mock_client = MagicMock()
        mock_range = MagicMock()
        mock_range.execute.return_value = MagicMock(
            data=[
                {"id": "uuid-1", "incident_id": "SEC-1"},
                {"id": "uuid-2", "incident_id": "SEC-2"},
            ]
        )
        mock_client.table.return_value.select.return_value.order.return_value.range.return_value = mock_range

        repo = IncidentRepository(client=mock_client)
        incidents = repo.list_incidents(limit=2, offset=0)
        self.assertEqual(len(incidents), 2)
        self.assertEqual(incidents[0]["incident_id"], "SEC-1")


if __name__ == "__main__":
    unittest.main()
