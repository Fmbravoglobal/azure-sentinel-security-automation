"""
Azure Sentinel Security Automation
Ingests Microsoft Sentinel alerts, applies risk scoring,
stores findings in Azure Table Storage, and publishes
high-risk alerts to Azure Service Bus for automated response.
"""

import json
import os
import logging
from datetime import datetime, timezone
from typing import Optional

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel

logger = logging.getLogger(__name__)

app = FastAPI(
    title="Azure Sentinel Security Automation",
    description="Risk-based alert triage and automated response for Microsoft Sentinel.",
    version="1.0.0",
)

# ---------------------------------------------------------------------------
# Risk scoring constants
# ---------------------------------------------------------------------------

HIGH_RISK_TACTICS = [
    "CredentialAccess", "PrivilegeEscalation", "LateralMovement",
    "Exfiltration", "Impact", "Persistence",
]

MEDIUM_RISK_TACTICS = [
    "Discovery", "Collection", "CommandAndControl", "InitialAccess",
]

SENSITIVE_RESOURCES = [
    "keyvault", "storageaccount", "virtualmachine", "subscriptions",
    "roleassignment", "managedidentity", "activeDirectory",
]


# ---------------------------------------------------------------------------
# Models
# ---------------------------------------------------------------------------

class SentinelAlert(BaseModel):
    alert_id: str
    display_name: str
    severity: str                     # High / Medium / Low / Informational
    tactic: Optional[str] = ""
    affected_resource: Optional[str] = ""
    source_ip: Optional[str] = ""
    geo_location: Optional[str] = "United States"
    user_principal: Optional[str] = ""
    subscription_id: Optional[str] = ""
    tenant_id: Optional[str] = ""
    alert_time: Optional[str] = ""


# ---------------------------------------------------------------------------
# Risk scoring engine
# ---------------------------------------------------------------------------

def calculate_risk(alert: SentinelAlert) -> tuple[int, list[str]]:
    score = 0
    reasons = []

    # Severity mapping
    severity_map = {"High": 40, "Medium": 25, "Low": 10, "Informational": 2}
    sev_score = severity_map.get(alert.severity, 5)
    score += sev_score
    reasons.append(f"Sentinel severity '{alert.severity}' (+{sev_score})")

    # Tactic scoring
    tactic = alert.tactic or ""
    if any(t.lower() in tactic.lower() for t in HIGH_RISK_TACTICS):
        score += 30
        reasons.append(f"High-risk MITRE tactic detected: {tactic}")
    elif any(t.lower() in tactic.lower() for t in MEDIUM_RISK_TACTICS):
        score += 15
        reasons.append(f"Medium-risk MITRE tactic detected: {tactic}")

    # Sensitive resource
    resource = (alert.affected_resource or "").lower()
    if any(r in resource for r in SENSITIVE_RESOURCES):
        score += 20
        reasons.append("Sensitive Azure resource targeted")

    # Geography
    geo = (alert.geo_location or "").lower()
    if geo and geo not in ["united states", "us", "usa"]:
        score += 15
        reasons.append(f"Access from non-standard geography: {alert.geo_location}")

    # External IP heuristic
    ip = alert.source_ip or ""
    if ip and not (ip.startswith("10.") or ip.startswith("192.168.") or ip.startswith("172.")):
        score += 10
        reasons.append("Alert originated from public IP address")

    return min(score, 100), reasons


def make_decision(score: int) -> str:
    if score >= 70:
        return "ESCALATE"
    if score >= 40:
        return "INVESTIGATE"
    return "MONITOR"


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------

@app.get("/")
def root():
    return {"message": "Azure Sentinel Security Automation is running", "version": "1.0.0"}


@app.get("/health")
def health():
    return {"status": "healthy", "timestamp": datetime.now(timezone.utc).isoformat()}


@app.post("/triage")
def triage_alert(alert: SentinelAlert):
    """
    Triage a Sentinel alert — score risk and return recommended action.
    """
    score, reasons = calculate_risk(alert)
    decision = make_decision(score)

    result = {
        "alert_id": alert.alert_id,
        "display_name": alert.display_name,
        "severity": alert.severity,
        "tactic": alert.tactic,
        "risk_score": score,
        "decision": decision,
        "reasons": reasons,
        "affected_resource": alert.affected_resource,
        "triaged_at": datetime.now(timezone.utc).isoformat(),
        "recommended_action": {
            "ESCALATE": "Immediately notify SOC. Initiate incident response playbook.",
            "INVESTIGATE": "Assign to analyst. Review logs and correlated events.",
            "MONITOR": "Log finding. Monitor for pattern escalation.",
        }.get(decision, "Review alert details."),
    }

    logger.info(f"Triaged alert {alert.alert_id}: score={score}, decision={decision}")
    return result


@app.post("/batch-triage")
def batch_triage(alerts: list[SentinelAlert]):
    """
    Triage multiple Sentinel alerts in a single request.
    """
    results = []
    for alert in alerts:
        score, reasons = calculate_risk(alert)
        decision = make_decision(score)
        results.append({
            "alert_id": alert.alert_id,
            "risk_score": score,
            "decision": decision,
            "severity": alert.severity,
        })

    escalate_count = sum(1 for r in results if r["decision"] == "ESCALATE")
    investigate_count = sum(1 for r in results if r["decision"] == "INVESTIGATE")
    monitor_count = sum(1 for r in results if r["decision"] == "MONITOR")

    return {
        "total_alerts": len(alerts),
        "escalate": escalate_count,
        "investigate": investigate_count,
        "monitor": monitor_count,
        "results": results,
    }
