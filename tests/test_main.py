"""
Unit tests for Azure Sentinel Security Automation.
"""

import sys
import os
import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from app.main import calculate_risk, make_decision, SentinelAlert


def make_alert(**overrides):
    defaults = dict(
        alert_id="alert-001",
        display_name="Test Alert",
        severity="Low",
        tactic="Discovery",
        affected_resource="storageaccount/mydata",
        source_ip="10.0.0.1",
        geo_location="United States",
        user_principal="user@corp.com",
    )
    defaults.update(overrides)
    return SentinelAlert(**defaults)


class TestRiskScoring:

    def test_high_severity_adds_score(self):
        alert = make_alert(severity="High")
        score, reasons = calculate_risk(alert)
        assert score >= 40
        assert any("High" in r for r in reasons)

    def test_low_severity_low_score(self):
        alert = make_alert(severity="Low", tactic="", affected_resource="", source_ip="10.0.0.1")
        score, _ = calculate_risk(alert)
        assert score < 40

    def test_credential_access_tactic_flagged(self):
        alert = make_alert(tactic="CredentialAccess")
        score, reasons = calculate_risk(alert)
        assert any("MITRE" in r for r in reasons)
        assert score >= 30

    def test_privilege_escalation_flagged(self):
        alert = make_alert(tactic="PrivilegeEscalation", severity="High")
        score, reasons = calculate_risk(alert)
        assert score >= 70

    def test_keyvault_resource_flagged(self):
        alert = make_alert(affected_resource="vaults/my-keyvault")
        score, reasons = calculate_risk(alert)
        assert any("Sensitive Azure resource" in r for r in reasons)

    def test_foreign_geography_flagged(self):
        alert = make_alert(geo_location="Russia")
        score, reasons = calculate_risk(alert)
        assert any("geography" in r for r in reasons)

    def test_public_ip_flagged(self):
        alert = make_alert(source_ip="185.220.101.1")
        score, reasons = calculate_risk(alert)
        assert any("public IP" in r for r in reasons)

    def test_private_ip_not_flagged(self):
        alert_pub = make_alert(source_ip="185.1.1.1")
        alert_priv = make_alert(source_ip="10.0.0.1")
        score_pub, _ = calculate_risk(alert_pub)
        score_priv, _ = calculate_risk(alert_priv)
        assert score_pub > score_priv

    def test_score_capped_at_100(self):
        alert = make_alert(
            severity="High", tactic="CredentialAccess",
            affected_resource="keyvault", geo_location="China",
            source_ip="185.1.1.1"
        )
        score, _ = calculate_risk(alert)
        assert score <= 100

    def test_score_non_negative(self):
        alert = make_alert(severity="Informational", tactic="", affected_resource="")
        score, _ = calculate_risk(alert)
        assert score >= 0


class TestDecision:

    def test_score_below_40_is_monitor(self):
        assert make_decision(39) == "MONITOR"
        assert make_decision(0) == "MONITOR"

    def test_score_40_to_69_is_investigate(self):
        assert make_decision(40) == "INVESTIGATE"
        assert make_decision(69) == "INVESTIGATE"

    def test_score_70_plus_is_escalate(self):
        assert make_decision(70) == "ESCALATE"
        assert make_decision(100) == "ESCALATE"


class TestAPIEndpoints:

    def test_triage_endpoint(self):
        from fastapi.testclient import TestClient
        from app.main import app
        client = TestClient(app)
        payload = {
            "alert_id": "test-001",
            "display_name": "Suspicious login",
            "severity": "High",
            "tactic": "CredentialAccess",
            "affected_resource": "keyvault/secrets",
            "source_ip": "185.1.2.3",
            "geo_location": "Russia",
        }
        response = client.post("/triage", json=payload)
        assert response.status_code == 200
        data = response.json()
        assert "risk_score" in data
        assert "decision" in data
        assert data["decision"] in ["ESCALATE", "INVESTIGATE", "MONITOR"]

    def test_health_endpoint(self):
        from fastapi.testclient import TestClient
        from app.main import app
        client = TestClient(app)
        response = client.get("/health")
        assert response.status_code == 200
        assert response.json()["status"] == "healthy"
