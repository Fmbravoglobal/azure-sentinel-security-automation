# Azure Sentinel Security Automation

[![Azure Sentinel Security Pipeline](https://github.com/Fmbravoglobal/azure-sentinel-security-automation/actions/workflows/security-pipeline.yml/badge.svg)](https://github.com/Fmbravoglobal/azure-sentinel-security-automation/actions/workflows/security-pipeline.yml)

## Overview

An automated security alert triage and response system built on **Microsoft Sentinel** and **Azure cloud-native services**. The platform ingests Sentinel alerts, applies a MITRE ATT&CK-aligned risk scoring engine, and routes high-risk findings to automated response workflows via Azure Service Bus.

Infrastructure is provisioned with **Terraform** and validated through a **GitHub Actions CI/CD security pipeline**.

---

## Architecture

```
Microsoft Sentinel Alert
         │
         ▼
┌─────────────────────────────────┐
│   FastAPI Triage Engine         │
│   MITRE ATT&CK Risk Scoring     │
│   Severity + Tactic + Resource  │
│   Geography + IP Analysis       │
└────────────┬────────────────────┘
             │
     ┌───────┴────────┐
     │                │
     ▼                ▼
ESCALATE (≥70)   INVESTIGATE (40-69)   MONITOR (<40)
     │
     ▼
Azure Service Bus
high-risk-alerts queue
     │
     ▼
Automated SOC Response
```

---

## Architecture Components

- **Microsoft Sentinel** — cloud-native SIEM and SOAR
- **Azure Log Analytics Workspace** — Sentinel data backend
- **Azure Key Vault** — secrets and credential storage
- **Azure Service Bus** — high-risk alert routing queue
- **Azure Storage Account** — findings archive
- **FastAPI** — risk scoring and triage API
- **Terraform** — Infrastructure as Code
- **GitHub Actions** — CI/CD security pipeline

---

## Security Workflow

1. Sentinel generates alert from log analytics data
2. Alert is sent to FastAPI triage engine via webhook
3. Risk score calculated using MITRE tactic, severity, resource sensitivity, geography
4. Decision made: ESCALATE / INVESTIGATE / MONITOR
5. ESCALATE alerts published to Service Bus queue
6. SOC team notified for immediate response

---

## Risk Scoring Model

| Factor | Max Points |
|---|---|
| Sentinel Severity (High=40, Medium=25, Low=10) | 40 |
| MITRE High-Risk Tactic (CredentialAccess, Exfiltration etc.) | 30 |
| Sensitive Resource (KeyVault, IAM, Storage) | 20 |
| Non-standard Geography | 15 |
| Public IP Address | 10 |
| **Total** | **100** |

**Decision thresholds:** ESCALATE ≥70 | INVESTIGATE 40-69 | MONITOR <40

---

## Technologies

- Microsoft Azure (Sentinel, Key Vault, Service Bus, Storage, Log Analytics)
- Python 3.11 · FastAPI · Pydantic
- Terraform (azurerm provider ~> 3.90)
- GitHub Actions CI/CD
- pytest unit testing

---

## CI/CD Pipeline

- `terraform fmt` — formatting validation
- `terraform validate` — schema validation
- **Checkov** — Azure security policy scanning
- **pytest** — unit tests for risk scoring logic

---

## Compliance Alignment

- NIST 800-53: IR-4, SI-4, AU-6
- CIS Azure Benchmark: 5.x (Logging), 8.x (Defender)
- SOC 2 Type II: CC7.2, CC7.3

---

## Author

**Oluwafemi Alabi Okunlola** | Cloud Security Engineer
[oluwafemiokunlola308@gmail.com](mailto:oluwafemiokunlola308@gmail.com)
