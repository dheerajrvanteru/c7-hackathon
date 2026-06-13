# CyberSentinel AI — System Architecture

## Overview

An AI-powered multi-agent cybersecurity system using LangGraph for orchestration, FastAPI for the backend, and a React analytics dashboard for the frontend.

## Architecture Layers

```
┌─────────────────────────────────────────────────────┐
│         React Dashboard (Vite + TailwindCSS)         │
│  Metrics · Agent Feed · Log Selector · Reports       │
└──────────────────────┬──────────────────────────────┘
                       │ HTTP / SSE
┌──────────────────────▼──────────────────────────────┐
│                   FastAPI Backend                    │
│   /analyze · /stream · /report · /agents/status      │
└──────────────────────┬──────────────────────────────┘
                       │ triggers
┌──────────────────────▼──────────────────────────────┐
│          LangGraph SecurityOrchestrator              │
│                                                      │
│  LogMonitor → ThreatIntel → VulnScanner              │
│            → IncidentResponse → PolicyChecker        │
│                                                      │
│  All agents share a SecurityState object             │
└──────┬───────────────────────────┬──────────────────┘
       │                           │
┌──────▼──────┐          ┌────────▼────────┐
│ Log Sources  │          │  External APIs   │
│ • Synthetic  │          │  • OpenRouter    │
│ • System     │          │    (gpt-4o)      │
│ • Upload     │          │  • NVD / CVE     │
└─────────────┘          │  • AbuseIPDB     │
                         └─────────────────┘
```

## Agent Flow

Each agent node reads from and writes to a shared `SecurityState` object:

| Agent | Input | Output to State |
|-------|-------|-----------------|
| Log Monitor | Raw logs | `anomalies[]`, `severity_map{}` |
| Threat Intel | Anomalies | `cve_matches[]`, `threat_score` |
| Vuln Scanner | Anomalies + CVEs | `vulnerabilities[]`, `risk_level` |
| Incident Response | All findings | `action_plan[]`, `runbook_md` |
| Policy Checker | All findings | `compliance_gaps[]`, `score%` |

## Streaming

`POST /analyze` returns immediately; LangGraph runs in a background thread. Agent wrappers emit `running` / `done` events to per-session queues consumed by `GET /stream/{session_id}`. The dashboard fetches `GET /report/{session_id}` after the `pipeline` `done` event.

## Tech Stack

- **Frontend:** React, Vite, TailwindCSS
- **Backend:** Python, FastAPI, SSE streaming
- **Orchestration:** LangGraph (state machine)
- **AI:** OpenRouter (`openai/gpt-4o` via `openai` Python SDK)
- **External Data:** NVD API, AbuseIPDB
- **Compliance Standards:** NIST CSF 2.0, SOC 2 Type II
