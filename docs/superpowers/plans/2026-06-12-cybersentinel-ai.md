# CyberSentinel AI Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build a multi-agent AI cybersecurity system that monitors logs, detects threats, scans vulnerabilities, generates incident response plans, and checks compliance — surfaced through a real-time analytics dashboard.

**Architecture:** Five LangGraph agent nodes share a `SecurityState` TypedDict that flows through the graph in sequence: LogMonitor → ThreatIntel → VulnScanner → IncidentResponse → PolicyChecker. FastAPI starts analysis in a **background task** and streams **live** agent events over SSE via per-session queues (`session_events.py`) while the React dashboard subscribes in parallel.

**Tech Stack:** Python 3.11, FastAPI, LangGraph, LangChain, OpenRouter (`openai/gpt-4o` via `openai` SDK), React, Vite, TailwindCSS, sse-starlette, pytest

**Caching + Evals:** All LLM calls go through `CachingLLMClient` (OpenRouter-backed `openai.OpenAI` client). An in-memory LRU cache (`LLMCache`) keyed on SHA-256 of model+messages eliminates redundant API calls on repeated runs. `EvalTracker` records tokens, cost (USD), and latency per call. `benchmark.py` runs the full agent prompt set uncached then cached and prints a comparison table — used to demo savings at the hackathon.

**Env vars:** `OPENROUTER_API_KEY`, `ABUSEIPDB_API_KEY`, `NVD_API_KEY` — no direct OpenAI API key.

---

## File Map

```
c7-hackathon/
├── backend/
│   ├── main.py                          # FastAPI app + SSE endpoints
│   ├── orchestrator.py                  # LangGraph graph definition
│   ├── state.py                         # SecurityState TypedDict
│   ├── llm_cache.py                     # ✅ DONE — LRU cache for LLM responses
│   ├── llm_client.py                    # ✅ DONE — CachingLLMClient (OpenRouter via openai SDK)
│   ├── eval_tracker.py                  # ✅ DONE — per-call token/cost/latency tracking
│   ├── benchmark.py                     # ✅ DONE — cached vs uncached eval benchmark
│   ├── session_events.py                # Per-session thread-safe queues for live SSE
│   ├── agents/
│   │   ├── __init__.py
│   │   ├── log_monitor.py               # Agent 1: parse + detect anomalies
│   │   ├── threat_intel.py              # Agent 2: CVE lookup + IP reputation
│   │   ├── vuln_scanner.py              # Agent 3: OWASP + headers + Docker
│   │   ├── incident_response.py         # Agent 4: action plan + runbook (uses CachingLLMClient)
│   │   └── policy_checker.py            # Agent 5: NIST + SOC2 compliance mapping
│   ├── tools/
│   │   ├── __init__.py
│   │   ├── nvd_api.py                   # NVD CVE search
│   │   ├── abuseipdb.py                 # IP reputation lookup
│   │   └── log_parser.py                # Log normalization utilities
│   ├── data/
│   │   └── synthetic_logs.json          # Pre-generated demo log fixtures
│   ├── tests/
│   │   ├── test_state.py
│   │   ├── test_log_monitor.py
│   │   ├── test_threat_intel.py
│   │   ├── test_vuln_scanner.py
│   │   ├── test_incident_response.py
│   │   ├── test_policy_checker.py
│   │   ├── test_orchestrator.py
│   │   ├── test_api.py
│   │   └── test_llm_cache.py            # Cache unit tests (LRU eviction, TTL, hit counting)
│   ├── requirements.txt
│   └── .env.example
├── frontend/
│   ├── src/
│   │   ├── App.tsx
│   │   ├── main.tsx
│   │   ├── components/
│   │   │   ├── LogSourceSelector.tsx    # Synthetic/System/Upload buttons
│   │   │   ├── MetricCard.tsx           # Single metric display card
│   │   │   ├── AgentFeed.tsx            # Live agent activity list
│   │   │   └── IncidentReport.tsx       # Action plan + compliance gaps panel
│   │   ├── hooks/
│   │   │   └── useSSE.ts                # SSE subscription + event parsing
│   │   └── types.ts                     # Shared TypeScript types
│   ├── index.html
│   ├── package.json
│   ├── vite.config.ts
│   └── tailwind.config.js
└── .env.example                         # OPENROUTER_API_KEY, ABUSEIPDB_API_KEY, NVD_API_KEY
```

---

## Task 1: Project Scaffold + Dependencies

**Files:**
- Create: `backend/requirements.txt`
- Create: `backend/.env.example`
- Create: `frontend/package.json`
- Create: `frontend/vite.config.ts`
- Create: `frontend/tailwind.config.js`
- Create: `frontend/index.html`
- Create: `frontend/src/main.tsx`

- [x] **Step 1: Create backend directory and requirements.txt** ✅ already created

```
backend/requirements.txt
```
```
fastapi==0.111.0
uvicorn[standard]==0.29.0
python-dotenv==1.0.1
langgraph==0.1.9
langchain==0.2.5
langchain-openai==0.1.8
openai==1.30.5
httpx==0.27.0
python-multipart==0.0.9
sse-starlette==1.8.2
pytest==8.2.2
pytest-asyncio==0.23.7
```

- [ ] **Step 2: Create .env.example**

```
backend/.env.example
```
```
OPENROUTER_API_KEY=sk-or-...
ABUSEIPDB_API_KEY=your_key_here
NVD_API_KEY=your_key_here
```

- [ ] **Step 3: Install backend dependencies**

```bash
cd backend && python -m venv .venv && source .venv/bin/activate && pip install -r requirements.txt
```
Expected: All packages install without error.

- [ ] **Step 4: Scaffold frontend with Vite**

```bash
cd frontend && npm create vite@latest . -- --template react-ts && npm install
```
Expected: `node_modules/` created, no errors.

- [ ] **Step 5: Install Tailwind**

```bash
cd frontend && npm install -D tailwindcss postcss autoprefixer && npx tailwindcss init -p
```

- [ ] **Step 6: Configure tailwind.config.js**

```js
// frontend/tailwind.config.js
/** @type {import('tailwindcss').Config} */
export default {
  content: ["./index.html", "./src/**/*.{ts,tsx}"],
  theme: { extend: {} },
  plugins: [],
}
```

- [ ] **Step 7: Add Tailwind directives to src/index.css**

```css
/* frontend/src/index.css */
@tailwind base;
@tailwind components;
@tailwind utilities;
```

- [ ] **Step 8: Commit scaffold**

```bash
git init
git add backend/requirements.txt backend/.env.example frontend/
git commit -m "chore: project scaffold — backend deps + vite/tailwind frontend"
```

---

## Task 1b: LLM Caching Layer + Eval Benchmark ✅ DONE

> **Status:** All four files already implemented and verified with `--dry-run`. No implementation needed — this task documents what was built and specifies the unit tests still to write.

**Files already created:**
- `backend/llm_cache.py` — `LLMCache` (LRU + TTL), `CacheEntry`, `get_default_cache()`
- `backend/llm_client.py` — `CachingLLMClient`, `CallMeta`
- `backend/eval_tracker.py` — `EvalTracker`, `compute_cost()`, `print_comparison_table()`
- `backend/benchmark.py` — two-pass benchmark (uncached → cached), `MockLLMClient` for dry runs

**Still to do:**

- [ ] **Step 1: Write cache unit tests**

```python
# backend/tests/test_llm_cache.py
import time
from llm_cache import LLMCache, CacheEntry

MODEL = "gpt-4o-mini"
MSGS = [{"role": "user", "content": "hello"}]

def _entry(**kwargs) -> CacheEntry:
    return CacheEntry(response={}, input_tokens=10, output_tokens=5, latency_ms=100, **kwargs)

def test_cache_miss_on_empty():
    c = LLMCache()
    assert c.get(MODEL, MSGS) is None
    assert c.misses == 1

def test_cache_hit_after_set():
    c = LLMCache()
    c.set(MODEL, MSGS, _entry())
    assert c.get(MODEL, MSGS) is not None
    assert c.hits == 1

def test_lru_eviction():
    c = LLMCache(max_size=2)
    for i in range(3):
        c.set(MODEL, [{"role": "user", "content": str(i)}], _entry())
    assert c.size == 2

def test_ttl_expiry():
    c = LLMCache(ttl_seconds=0.05)
    c.set(MODEL, MSGS, _entry())
    time.sleep(0.1)
    assert c.get(MODEL, MSGS) is None
    assert c.misses == 1

def test_hit_rate():
    c = LLMCache()
    c.set(MODEL, MSGS, _entry())
    c.get(MODEL, MSGS)  # hit
    c.get(MODEL, [{"role": "user", "content": "other"}])  # miss
    assert c.hit_rate == 0.5

def test_different_messages_different_keys():
    c = LLMCache()
    msgs_a = [{"role": "user", "content": "A"}]
    msgs_b = [{"role": "user", "content": "B"}]
    c.set(MODEL, msgs_a, _entry())
    assert c.get(MODEL, msgs_b) is None
```

- [ ] **Step 2: Run cache unit tests**

```bash
cd backend && .venv/bin/python -m pytest tests/test_llm_cache.py -v
```
Expected: 6 PASS

- [ ] **Step 3: Run benchmark dry-run and assert output**

```bash
cd backend && .venv/bin/python benchmark.py --dry-run --model openai/gpt-4o-mini
```
Expected: All 5 agents show `✓ cache` in the cached pass, savings callout shows > 0% cost reduction, cached latency < 10 ms/call.

- [ ] **Step 4: Commit**

```bash
git add backend/llm_cache.py backend/llm_client.py backend/eval_tracker.py backend/benchmark.py backend/tests/test_llm_cache.py
git commit -m "feat: LLM caching layer (LRU cache + CachingLLMClient) + eval benchmark"
```

---

## Task 2: SecurityState + synthetic log data

**Files:**
- Create: `backend/state.py`
- Create: `backend/data/synthetic_logs.json`
- Create: `backend/tests/test_state.py`

- [ ] **Step 1: Write failing test for SecurityState**

```python
# backend/tests/test_state.py
from state import SecurityState, make_initial_state

def test_make_initial_state_sets_required_fields():
    state = make_initial_state(raw_logs=["log line 1"], log_source="synthetic", session_id="abc123")
    assert state["raw_logs"] == ["log line 1"]
    assert state["log_source"] == "synthetic"
    assert state["session_id"] == "abc123"
    assert state["anomalies"] == []
    assert state["cve_matches"] == []
    assert state["vulnerabilities"] == []
    assert state["action_plan"] == []
    assert state["compliance_gaps"] == []
    assert state["threat_score"] == 0
    assert state["compliance_score"] == 0
```

- [ ] **Step 2: Run test to verify it fails**

```bash
cd backend && python -m pytest tests/test_state.py -v
```
Expected: FAIL — `ModuleNotFoundError: No module named 'state'`

- [ ] **Step 3: Implement state.py**

```python
# backend/state.py
from typing import TypedDict

class SecurityState(TypedDict):
    raw_logs: list[str]
    log_source: str
    session_id: str
    anomalies: list[dict]
    severity_map: dict[str, str]
    cve_matches: list[dict]
    threat_score: int
    vulnerabilities: list[dict]
    risk_level: str
    action_plan: list[str]
    runbook_md: str
    compliance_gaps: list[dict]
    compliance_score: int

def make_initial_state(raw_logs: list[str], log_source: str, session_id: str) -> SecurityState:
    return SecurityState(
        raw_logs=raw_logs,
        log_source=log_source,
        session_id=session_id,
        anomalies=[],
        severity_map={},
        cve_matches=[],
        threat_score=0,
        vulnerabilities=[],
        risk_level="low",
        action_plan=[],
        runbook_md="",
        compliance_gaps=[],
        compliance_score=0,
    )
```

- [ ] **Step 4: Create synthetic_logs.json**

```json
[
  "Jun 12 10:00:01 server sshd[1234]: Failed password for root from 192.168.1.42 port 4444 ssh2",
  "Jun 12 10:00:02 server sshd[1234]: Failed password for root from 192.168.1.42 port 4444 ssh2",
  "Jun 12 10:00:03 server sshd[1234]: Failed password for root from 192.168.1.42 port 4444 ssh2",
  "Jun 12 10:00:04 server sshd[1234]: Failed password for admin from 192.168.1.42 port 4444 ssh2",
  "Jun 12 10:00:05 server sshd[1234]: Failed password for ubuntu from 192.168.1.42 port 4444 ssh2",
  "Jun 12 10:01:00 server kernel: Nmap scan detected from 10.0.0.5",
  "Jun 12 10:01:30 server nginx[5678]: 404 /etc/passwd HTTP/1.1 from 10.0.0.99",
  "Jun 12 10:02:00 server sudo[9012]: FAILED su for user root by www-data",
  "Jun 12 10:03:00 server sshd[1234]: Accepted password for deploy from 203.0.113.1 port 22 ssh2",
  "Jun 12 10:04:00 server nginx[5678]: GET /api/health HTTP/1.1 200 from 127.0.0.1"
]
```

- [ ] **Step 5: Run tests to verify they pass**

```bash
cd backend && python -m pytest tests/test_state.py -v
```
Expected: PASS

- [ ] **Step 6: Commit**

```bash
git add backend/state.py backend/data/synthetic_logs.json backend/tests/test_state.py
git commit -m "feat: SecurityState TypedDict + synthetic log fixtures"
```

---

## Task 3: Log Parser Tool + Log Monitor Agent

**Files:**
- Create: `backend/tools/log_parser.py`
- Create: `backend/agents/log_monitor.py`
- Create: `backend/agents/__init__.py`
- Create: `backend/tools/__init__.py`
- Create: `backend/tests/test_log_monitor.py`

- [ ] **Step 1: Write failing tests**

```python
# backend/tests/test_log_monitor.py
import pytest
from tools.log_parser import parse_log_line, detect_anomalies
from agents.log_monitor import run_log_monitor
from state import make_initial_state

def test_parse_log_line_ssh_failure():
    line = "Jun 12 10:00:01 server sshd[1234]: Failed password for root from 192.168.1.42 port 4444 ssh2"
    result = parse_log_line(line)
    assert result["type"] == "ssh_failure"
    assert result["source_ip"] == "192.168.1.42"
    assert result["user"] == "root"

def test_parse_log_line_port_scan():
    line = "Jun 12 10:01:00 server kernel: Nmap scan detected from 10.0.0.5"
    result = parse_log_line(line)
    assert result["type"] == "port_scan"
    assert result["source_ip"] == "10.0.0.5"

def test_detect_anomalies_brute_force():
    events = [
        {"type": "ssh_failure", "source_ip": "192.168.1.42", "user": "root"},
        {"type": "ssh_failure", "source_ip": "192.168.1.42", "user": "admin"},
        {"type": "ssh_failure", "source_ip": "192.168.1.42", "user": "ubuntu"},
    ]
    anomalies = detect_anomalies(events)
    assert any(a["type"] == "brute_force" and a["source_ip"] == "192.168.1.42" for a in anomalies)

def test_run_log_monitor_populates_state():
    state = make_initial_state(
        raw_logs=[
            "Jun 12 10:00:01 server sshd[1234]: Failed password for root from 192.168.1.42 port 4444 ssh2",
            "Jun 12 10:00:02 server sshd[1234]: Failed password for root from 192.168.1.42 port 4444 ssh2",
            "Jun 12 10:00:03 server sshd[1234]: Failed password for root from 192.168.1.42 port 4444 ssh2",
        ],
        log_source="synthetic",
        session_id="test-001"
    )
    result = run_log_monitor(state)
    assert len(result["anomalies"]) > 0
    assert len(result["severity_map"]) > 0
```

- [ ] **Step 2: Run tests to verify they fail**

```bash
cd backend && python -m pytest tests/test_log_monitor.py -v
```
Expected: FAIL — `ModuleNotFoundError`

- [ ] **Step 3: Implement log_parser.py**

```python
# backend/tools/log_parser.py
import re
from collections import defaultdict

SSH_FAIL_RE = re.compile(r"Failed password for (\S+) from ([\d.]+)")
PORT_SCAN_RE = re.compile(r"Nmap scan detected from ([\d.]+)")
PATH_TRAVERSE_RE = re.compile(r"(\d{3}) (/etc/\S+|/proc/\S+|\.\./) HTTP")
SUDO_FAIL_RE = re.compile(r"FAILED su for user (\S+) by (\S+)")

def parse_log_line(line: str) -> dict:
    if m := SSH_FAIL_RE.search(line):
        return {"type": "ssh_failure", "user": m.group(1), "source_ip": m.group(2), "raw": line}
    if m := PORT_SCAN_RE.search(line):
        return {"type": "port_scan", "source_ip": m.group(1), "raw": line}
    if m := PATH_TRAVERSE_RE.search(line):
        return {"type": "path_traversal", "path": m.group(2), "raw": line}
    if m := SUDO_FAIL_RE.search(line):
        return {"type": "sudo_failure", "user": m.group(1), "by": m.group(2), "raw": line}
    return {"type": "info", "raw": line}

def detect_anomalies(events: list[dict]) -> list[dict]:
    anomalies = []
    ip_failures: dict[str, int] = defaultdict(int)

    for e in events:
        if e["type"] == "ssh_failure":
            ip_failures[e["source_ip"]] += 1
        elif e["type"] in ("port_scan", "path_traversal", "sudo_failure"):
            anomalies.append({
                "type": e["type"],
                "source_ip": e.get("source_ip", "unknown"),
                "detail": e.get("path") or e.get("by") or "",
                "severity": "HIGH",
            })

    for ip, count in ip_failures.items():
        if count >= 3:
            anomalies.append({
                "type": "brute_force",
                "source_ip": ip,
                "attempt_count": count,
                "severity": "CRITICAL",
            })

    return anomalies
```

- [ ] **Step 4: Implement log_monitor.py**

```python
# backend/agents/log_monitor.py
from state import SecurityState
from tools.log_parser import parse_log_line, detect_anomalies

SEVERITY_ORDER = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1}

def run_log_monitor(state: SecurityState) -> SecurityState:
    events = [parse_log_line(line) for line in state["raw_logs"]]
    anomalies = detect_anomalies(events)
    severity_map = {a["type"]: a["severity"] for a in anomalies}
    return {**state, "anomalies": anomalies, "severity_map": severity_map}
```

- [ ] **Step 5: Create empty __init__.py files**

```bash
touch backend/agents/__init__.py backend/tools/__init__.py
```

- [ ] **Step 6: Run tests to verify they pass**

```bash
cd backend && python -m pytest tests/test_log_monitor.py -v
```
Expected: 4 PASS

- [ ] **Step 7: Commit**

```bash
git add backend/tools/log_parser.py backend/tools/__init__.py backend/agents/log_monitor.py backend/agents/__init__.py backend/tests/test_log_monitor.py
git commit -m "feat: log parser tool + log monitor agent"
```

---

## Task 4: NVD + AbuseIPDB Tools + Threat Intel Agent

**Files:**
- Create: `backend/tools/nvd_api.py`
- Create: `backend/tools/abuseipdb.py`
- Create: `backend/agents/threat_intel.py`
- Create: `backend/tests/test_threat_intel.py`

- [ ] **Step 1: Write failing tests**

```python
# backend/tests/test_threat_intel.py
import pytest
from unittest.mock import patch, AsyncMock
from agents.threat_intel import run_threat_intel
from state import make_initial_state

MOCK_CVE = {
    "id": "CVE-2024-1234",
    "description": "SSH brute force vulnerability",
    "cvss_score": 9.1,
}

def test_run_threat_intel_populates_cve_matches():
    state = make_initial_state(raw_logs=[], log_source="synthetic", session_id="t1")
    state = {**state, "anomalies": [{"type": "brute_force", "source_ip": "192.168.1.42", "severity": "CRITICAL"}]}

    with patch("tools.nvd_api.search_nvd_cve", return_value=[MOCK_CVE]):
        with patch("tools.abuseipdb.check_ip_reputation", return_value={"score": 90, "flagged": True}):
            result = run_threat_intel(state)

    assert len(result["cve_matches"]) > 0
    assert result["threat_score"] > 0

def test_run_threat_intel_no_anomalies_returns_zero_score():
    state = make_initial_state(raw_logs=[], log_source="synthetic", session_id="t2")
    with patch("tools.nvd_api.search_nvd_cve", return_value=[]):
        with patch("tools.abuseipdb.check_ip_reputation", return_value={"score": 0, "flagged": False}):
            result = run_threat_intel(state)
    assert result["threat_score"] == 0
```

- [ ] **Step 2: Run tests to verify they fail**

```bash
cd backend && python -m pytest tests/test_threat_intel.py -v
```
Expected: FAIL — `ModuleNotFoundError`

- [ ] **Step 3: Implement nvd_api.py**

```python
# backend/tools/nvd_api.py
import httpx
import os

NVD_BASE = "https://services.nvd.nist.gov/rest/json/cves/2.0"

def search_nvd_cve(keyword: str) -> list[dict]:
    """Search NVD for CVEs matching keyword. Returns list of simplified CVE dicts."""
    params = {"keywordSearch": keyword, "resultsPerPage": 5}
    headers = {}
    api_key = os.getenv("NVD_API_KEY")
    if api_key:
        headers["apiKey"] = api_key
    try:
        resp = httpx.get(NVD_BASE, params=params, headers=headers, timeout=10)
        resp.raise_for_status()
        items = resp.json().get("vulnerabilities", [])
        results = []
        for item in items:
            cve = item.get("cve", {})
            desc = next(
                (d["value"] for d in cve.get("descriptions", []) if d["lang"] == "en"),
                ""
            )
            metrics = cve.get("metrics", {})
            cvss = 0.0
            if "cvssMetricV31" in metrics:
                cvss = metrics["cvssMetricV31"][0]["cvssData"]["baseScore"]
            elif "cvssMetricV2" in metrics:
                cvss = metrics["cvssMetricV2"][0]["cvssData"]["baseScore"]
            results.append({"id": cve["id"], "description": desc, "cvss_score": cvss})
        return results
    except Exception:
        return []
```

- [ ] **Step 4: Implement abuseipdb.py**

```python
# backend/tools/abuseipdb.py
import httpx
import os

ABUSEIPDB_BASE = "https://api.abuseipdb.com/api/v2/check"

def check_ip_reputation(ip: str) -> dict:
    """Check IP reputation via AbuseIPDB. Returns score and flagged status."""
    api_key = os.getenv("ABUSEIPDB_API_KEY", "")
    if not api_key:
        return {"score": 0, "flagged": False, "note": "no api key"}
    try:
        resp = httpx.get(
            ABUSEIPDB_BASE,
            headers={"Key": api_key, "Accept": "application/json"},
            params={"ipAddress": ip, "maxAgeInDays": 90},
            timeout=10,
        )
        resp.raise_for_status()
        data = resp.json().get("data", {})
        score = data.get("abuseConfidenceScore", 0)
        return {"score": score, "flagged": score > 50, "country": data.get("countryCode", "")}
    except Exception:
        return {"score": 0, "flagged": False, "note": "api error"}
```

- [ ] **Step 5: Implement threat_intel.py**

```python
# backend/agents/threat_intel.py
from state import SecurityState
from tools.nvd_api import search_nvd_cve
from tools.abuseipdb import check_ip_reputation

ANOMALY_KEYWORDS = {
    "brute_force": "SSH brute force",
    "port_scan": "port scan network reconnaissance",
    "path_traversal": "path traversal directory",
    "sudo_failure": "privilege escalation sudo",
}

def run_threat_intel(state: SecurityState) -> SecurityState:
    anomalies = state["anomalies"]
    cve_matches = []
    ip_scores = []

    for anomaly in anomalies:
        keyword = ANOMALY_KEYWORDS.get(anomaly["type"], anomaly["type"])
        cves = search_nvd_cve(keyword)
        for cve in cves:
            cve_matches.append({**cve, "linked_anomaly": anomaly["type"]})

        ip = anomaly.get("source_ip")
        if ip and ip not in ("unknown", "127.0.0.1"):
            rep = check_ip_reputation(ip)
            ip_scores.append(rep["score"])

    threat_score = min(100, int(sum(ip_scores) / max(len(ip_scores), 1)) + len(cve_matches) * 5)
    return {**state, "cve_matches": cve_matches, "threat_score": threat_score}
```

- [ ] **Step 6: Run tests to verify they pass**

```bash
cd backend && python -m pytest tests/test_threat_intel.py -v
```
Expected: 2 PASS

- [ ] **Step 7: Commit**

```bash
git add backend/tools/nvd_api.py backend/tools/abuseipdb.py backend/agents/threat_intel.py backend/tests/test_threat_intel.py
git commit -m "feat: NVD + AbuseIPDB tools + threat intel agent"
```

---

## Task 5: Vulnerability Scanner Agent

**Files:**
- Create: `backend/agents/vuln_scanner.py`
- Create: `backend/tests/test_vuln_scanner.py`

- [ ] **Step 1: Write failing tests**

```python
# backend/tests/test_vuln_scanner.py
from agents.vuln_scanner import run_vuln_scanner, check_api_headers, scan_for_owasp
from state import make_initial_state

def test_scan_for_owasp_path_traversal():
    anomalies = [{"type": "path_traversal", "detail": "/etc/passwd", "severity": "HIGH"}]
    vulns = scan_for_owasp(anomalies)
    assert any(v["category"] == "OWASP-A01" for v in vulns)

def test_check_api_headers_missing():
    headers = {"Content-Type": "application/json"}
    findings = check_api_headers(headers)
    assert any(f["header"] == "X-Frame-Options" for f in findings)
    assert any(f["header"] == "Content-Security-Policy" for f in findings)

def test_run_vuln_scanner_populates_state():
    state = make_initial_state(raw_logs=[], log_source="synthetic", session_id="v1")
    state = {**state, "anomalies": [
        {"type": "path_traversal", "detail": "/etc/passwd", "severity": "HIGH"},
        {"type": "brute_force", "source_ip": "1.2.3.4", "severity": "CRITICAL"},
    ]}
    result = run_vuln_scanner(state)
    assert len(result["vulnerabilities"]) > 0
    assert result["risk_level"] in ("low", "medium", "high", "critical")
```

- [ ] **Step 2: Run tests to verify they fail**

```bash
cd backend && python -m pytest tests/test_vuln_scanner.py -v
```
Expected: FAIL — `ModuleNotFoundError`

- [ ] **Step 3: Implement vuln_scanner.py**

```python
# backend/agents/vuln_scanner.py
from state import SecurityState

OWASP_MAP = {
    "path_traversal": {"category": "OWASP-A01", "name": "Broken Access Control", "severity": "HIGH"},
    "sudo_failure": {"category": "OWASP-A07", "name": "Identification and Authentication Failures", "severity": "HIGH"},
    "brute_force": {"category": "OWASP-A07", "name": "Identification and Authentication Failures", "severity": "CRITICAL"},
    "port_scan": {"category": "OWASP-A05", "name": "Security Misconfiguration", "severity": "MEDIUM"},
}

REQUIRED_HEADERS = [
    "X-Frame-Options",
    "Content-Security-Policy",
    "X-Content-Type-Options",
    "Strict-Transport-Security",
]

def scan_for_owasp(anomalies: list[dict]) -> list[dict]:
    seen = set()
    vulns = []
    for a in anomalies:
        mapping = OWASP_MAP.get(a["type"])
        if mapping and mapping["category"] not in seen:
            seen.add(mapping["category"])
            vulns.append({**mapping, "linked_anomaly": a["type"]})
    return vulns

def check_api_headers(headers: dict) -> list[dict]:
    missing = []
    for h in REQUIRED_HEADERS:
        if h not in headers:
            missing.append({"header": h, "severity": "MEDIUM", "recommendation": f"Add {h} response header"})
    return missing

def _compute_risk_level(vulns: list[dict]) -> str:
    if any(v["severity"] == "CRITICAL" for v in vulns):
        return "critical"
    if any(v["severity"] == "HIGH" for v in vulns):
        return "high"
    if any(v["severity"] == "MEDIUM" for v in vulns):
        return "medium"
    return "low"

def run_vuln_scanner(state: SecurityState) -> SecurityState:
    owasp_vulns = scan_for_owasp(state["anomalies"])
    # Default headers check against common missing headers (no live URL in demo mode)
    header_vulns = check_api_headers({})
    vulnerabilities = owasp_vulns + header_vulns
    risk_level = _compute_risk_level(vulnerabilities)
    return {**state, "vulnerabilities": vulnerabilities, "risk_level": risk_level}
```

- [ ] **Step 4: Run tests to verify they pass**

```bash
cd backend && python -m pytest tests/test_vuln_scanner.py -v
```
Expected: 3 PASS

- [ ] **Step 5: Commit**

```bash
git add backend/agents/vuln_scanner.py backend/tests/test_vuln_scanner.py
git commit -m "feat: vulnerability scanner agent (OWASP + header checks)"
```

---

## Task 6: Incident Response Agent

**Files:**
- Create: `backend/agents/incident_response.py`
- Create: `backend/tests/test_incident_response.py`

- [ ] **Step 1: Write failing tests**

```python
# backend/tests/test_incident_response.py
from unittest.mock import patch
from agents.incident_response import run_incident_response, build_prompt
from state import make_initial_state

MOCK_PLAN = "1. Block IP 192.168.1.42\n2. Rotate SSH keys\n3. Enable 2FA"

def test_build_prompt_includes_anomalies_and_cves():
    state = make_initial_state(raw_logs=[], log_source="synthetic", session_id="ir1")
    state = {**state,
        "anomalies": [{"type": "brute_force", "source_ip": "192.168.1.42", "severity": "CRITICAL"}],
        "cve_matches": [{"id": "CVE-2024-1234", "cvss_score": 9.1, "description": "SSH vuln"}],
        "vulnerabilities": [{"category": "OWASP-A07", "name": "Auth Failures", "severity": "CRITICAL"}],
        "threat_score": 75,
    }
    prompt = build_prompt(state)
    assert "brute_force" in prompt
    assert "CVE-2024-1234" in prompt
    assert "OWASP-A07" in prompt

def test_run_incident_response_populates_action_plan():
    state = make_initial_state(raw_logs=[], log_source="synthetic", session_id="ir2")
    state = {**state,
        "anomalies": [{"type": "brute_force", "source_ip": "192.168.1.42", "severity": "CRITICAL"}],
        "cve_matches": [],
        "vulnerabilities": [],
        "threat_score": 50,
    }
    mock_response = "1. Block IP\n2. Rotate keys\n3. Enable 2FA"
    with patch("agents.incident_response.call_openai", return_value=mock_response):
        result = run_incident_response(state)
    assert len(result["action_plan"]) == 3
    assert "Block IP" in result["action_plan"][0]
    assert len(result["runbook_md"]) > 0
```

- [ ] **Step 2: Run tests to verify they fail**

```bash
cd backend && python -m pytest tests/test_incident_response.py -v
```
Expected: FAIL — `ModuleNotFoundError`

- [ ] **Step 3: Implement incident_response.py**

```python
# backend/agents/incident_response.py
import os
from state import SecurityState
from llm_client import CachingLLMClient
from llm_cache import get_default_cache

_llm = CachingLLMClient(
    api_key=os.getenv("OPENROUTER_API_KEY"),
    base_url="https://openrouter.ai/api/v1",
    cache=get_default_cache(),
)

def call_openai(prompt: str) -> str:
    messages = [
        {"role": "system", "content": "You are a senior security incident responder. Be concise and actionable."},
        {"role": "user", "content": prompt},
    ]
    response, _meta = _llm.chat(
        agent="incident_response",
        model="openai/gpt-4o",
        messages=messages,
        temperature=0.2,
    )
    return _llm.extract_text(response)

def build_prompt(state: SecurityState) -> str:
    anomaly_lines = "\n".join(f"- {a['type']} from {a.get('source_ip','?')} ({a['severity']})" for a in state["anomalies"])
    cve_lines = "\n".join(f"- {c['id']} CVSS:{c['cvss_score']} — {c['description'][:80]}" for c in state["cve_matches"])
    vuln_lines = "\n".join(f"- {v.get('category','?')} {v.get('name','?')} ({v['severity']})" for v in state["vulnerabilities"])
    return f"""Security incident analysis:

ANOMALIES DETECTED:
{anomaly_lines or 'None'}

CVE MATCHES:
{cve_lines or 'None'}

VULNERABILITIES:
{vuln_lines or 'None'}

THREAT SCORE: {state['threat_score']}/100

Provide a numbered action plan (5-7 steps) to remediate these issues immediately. Be specific and actionable."""

def run_incident_response(state: SecurityState) -> SecurityState:
    prompt = build_prompt(state)
    raw = call_openai(prompt)
    lines = [l.strip() for l in raw.strip().split("\n") if l.strip() and l.strip()[0].isdigit()]
    action_plan = [l.split(". ", 1)[-1] if ". " in l else l for l in lines]
    runbook_md = f"# Incident Response Runbook\n\n## Action Plan\n\n" + "\n".join(f"{i+1}. {step}" for i, step in enumerate(action_plan))
    return {**state, "action_plan": action_plan, "runbook_md": runbook_md}
```

- [ ] **Step 4: Run tests to verify they pass**

```bash
cd backend && python -m pytest tests/test_incident_response.py -v
```
Expected: 2 PASS

- [ ] **Step 5: Commit**

```bash
git add backend/agents/incident_response.py backend/tests/test_incident_response.py
git commit -m "feat: incident response agent with OpenRouter gpt-4o action plan generation"
```

---

## Task 7: Policy Checker Agent

**Files:**
- Create: `backend/agents/policy_checker.py`
- Create: `backend/tests/test_policy_checker.py`

- [ ] **Step 1: Write failing tests**

```python
# backend/tests/test_policy_checker.py
from agents.policy_checker import run_policy_checker, map_to_nist, map_to_soc2
from state import make_initial_state

def test_map_to_nist_brute_force():
    anomalies = [{"type": "brute_force", "severity": "CRITICAL"}]
    gaps = map_to_nist(anomalies)
    ids = [g["control_id"] for g in gaps]
    assert "PR.AC-1" in ids or "DE.CM-1" in ids

def test_map_to_soc2_auth_failure():
    anomalies = [{"type": "brute_force", "severity": "CRITICAL"}]
    gaps = map_to_soc2(anomalies)
    ids = [g["control_id"] for g in gaps]
    assert "CC6.1" in ids

def test_run_policy_checker_produces_score():
    state = make_initial_state(raw_logs=[], log_source="synthetic", session_id="pc1")
    state = {**state,
        "anomalies": [{"type": "brute_force", "severity": "CRITICAL"}],
        "cve_matches": [{"id": "CVE-2024-1234", "cvss_score": 9.1}],
        "vulnerabilities": [{"category": "OWASP-A07", "severity": "CRITICAL"}],
        "risk_level": "critical",
        "action_plan": ["Block IP", "Rotate keys"],
    }
    result = run_policy_checker(state)
    assert 0 <= result["compliance_score"] <= 100
    assert len(result["compliance_gaps"]) > 0
    assert all("framework" in g for g in result["compliance_gaps"])
```

- [ ] **Step 2: Run tests to verify they fail**

```bash
cd backend && python -m pytest tests/test_policy_checker.py -v
```
Expected: FAIL — `ModuleNotFoundError`

- [ ] **Step 3: Implement policy_checker.py**

```python
# backend/agents/policy_checker.py
from state import SecurityState

NIST_MAP = {
    "brute_force":     [("PR.AC-1", "Identities and credentials are managed"), ("DE.CM-1", "Network is monitored")],
    "port_scan":       [("DE.CM-1", "Network is monitored"), ("PR.PT-4", "Communications protected")],
    "path_traversal":  [("PR.AC-4", "Access permissions managed"), ("PR.DS-5", "Protections against data leaks")],
    "sudo_failure":    [("PR.AC-1", "Identities and credentials managed"), ("PR.AC-6", "Identities are proofed")],
}

SOC2_MAP = {
    "brute_force":     [("CC6.1", "Logical access security"), ("CC7.2", "Monitors system components")],
    "port_scan":       [("CC6.6", "Unauthorized access prevented"), ("CC7.2", "Monitors system components")],
    "path_traversal":  [("CC6.1", "Logical access security"), ("CC6.3", "Access removed when no longer needed")],
    "sudo_failure":    [("CC6.1", "Logical access security"), ("CC6.2", "Prior to issuing credentials")],
}

def map_to_nist(anomalies: list[dict]) -> list[dict]:
    seen, gaps = set(), []
    for a in anomalies:
        for control_id, desc in NIST_MAP.get(a["type"], []):
            if control_id not in seen:
                seen.add(control_id)
                gaps.append({"framework": "NIST CSF 2.0", "control_id": control_id, "description": desc, "severity": a["severity"]})
    return gaps

def map_to_soc2(anomalies: list[dict]) -> list[dict]:
    seen, gaps = set(), []
    for a in anomalies:
        for control_id, desc in SOC2_MAP.get(a["type"], []):
            if control_id not in seen:
                seen.add(control_id)
                gaps.append({"framework": "SOC 2 Type II", "control_id": control_id, "description": desc, "severity": a["severity"]})
    return gaps

def run_policy_checker(state: SecurityState) -> SecurityState:
    anomalies = state["anomalies"]
    gaps = map_to_nist(anomalies) + map_to_soc2(anomalies)
    score = max(0, 100 - len(gaps) * 5)
    return {**state, "compliance_gaps": gaps, "compliance_score": score}
```

- [ ] **Step 4: Run tests to verify they pass**

```bash
cd backend && python -m pytest tests/test_policy_checker.py -v
```
Expected: 3 PASS

- [ ] **Step 5: Commit**

```bash
git add backend/agents/policy_checker.py backend/tests/test_policy_checker.py
git commit -m "feat: policy checker agent (NIST CSF + SOC2 compliance mapping)"
```

---

## Task 8: Session Events + LangGraph Orchestrator

**Files:**
- Create: `backend/session_events.py`
- Create: `backend/orchestrator.py`
- Create: `backend/tests/test_orchestrator.py`

- [ ] **Step 1: Write failing integration test**

```python
# backend/tests/test_orchestrator.py
import json
from unittest.mock import patch
from orchestrator import run_analysis

MOCK_PLAN = "1. Block IP\n2. Rotate SSH keys\n3. Enable 2FA\n4. Update nginx\n5. Add headers"

def test_run_analysis_populates_all_state_fields():
    with open("data/synthetic_logs.json") as f:
        logs = json.load(f)

    with patch("tools.nvd_api.search_nvd_cve", return_value=[]):
        with patch("tools.abuseipdb.check_ip_reputation", return_value={"score": 0, "flagged": False}):
            with patch("agents.incident_response.call_openai", return_value=MOCK_PLAN):
                state = run_analysis(logs=logs, log_source="synthetic", session_id="orch-test")

    assert len(state["anomalies"]) > 0
    assert len(state["compliance_gaps"]) > 0
    assert len(state["action_plan"]) > 0
    assert 0 <= state["compliance_score"] <= 100
    assert state["risk_level"] in ("low", "medium", "high", "critical")
    assert state["session_id"] == "orch-test"
```

- [ ] **Step 2: Run test to verify it fails**

```bash
cd backend && .venv/bin/python -m pytest tests/test_orchestrator.py -v
```
Expected: FAIL — `ModuleNotFoundError: No module named 'orchestrator'`

- [ ] **Step 3: Implement session_events.py**

```python
# backend/session_events.py
import queue
from datetime import datetime, timezone
from typing import Any

_queues: dict[str, queue.Queue] = {}
_status: dict[str, dict[str, str]] = {}

def create_session(session_id: str) -> queue.Queue:
    q: queue.Queue = queue.Queue()
    _queues[session_id] = q
    _status[session_id] = {
        "log_monitor": "pending",
        "threat_intel": "pending",
        "vuln_scanner": "pending",
        "incident_response": "pending",
        "policy_checker": "pending",
    }
    return q

def get_queue(session_id: str) -> queue.Queue | None:
    return _queues.get(session_id)

def get_agent_status(session_id: str) -> dict[str, str]:
    return _status.get(session_id, {})

def emit_sync(session_id: str, agent: str, status: str, findings: list | None = None) -> None:
    q = _queues.get(session_id)
    if not q:
        return
    if agent in _status.get(session_id, {}):
        _status[session_id][agent] = status
    q.put({
        "agent": agent,
        "status": status,
        "findings": findings or [],
        "timestamp": datetime.now(timezone.utc).isoformat(),
    })

def close_session(session_id: str) -> None:
    q = _queues.get(session_id)
    if q:
        q.put(None)
```

- [ ] **Step 4: Implement orchestrator.py with SSE-emitting wrappers**

```python
# backend/orchestrator.py
from langgraph.graph import StateGraph, END
from state import SecurityState, make_initial_state
from session_events import emit_sync, close_session
from agents.log_monitor import run_log_monitor
from agents.threat_intel import run_threat_intel
from agents.vuln_scanner import run_vuln_scanner
from agents.incident_response import run_incident_response
from agents.policy_checker import run_policy_checker

AGENTS = [
    ("log_monitor", run_log_monitor),
    ("threat_intel", run_threat_intel),
    ("vuln_scanner", run_vuln_scanner),
    ("incident_response", run_incident_response),
    ("policy_checker", run_policy_checker),
]

def _wrap(agent_name: str, fn):
    def node(state: SecurityState) -> SecurityState:
        session_id = state["session_id"]
        emit_sync(session_id, agent_name, "running")
        try:
            result = fn(state)
            emit_sync(session_id, agent_name, "done")
            return result
        except Exception:
            emit_sync(session_id, agent_name, "error")
            raise
    return node

def build_graph():
    graph = StateGraph(SecurityState)
    for name, fn in AGENTS:
        graph.add_node(name, _wrap(name, fn))
    graph.set_entry_point("log_monitor")
    graph.add_edge("log_monitor", "threat_intel")
    graph.add_edge("threat_intel", "vuln_scanner")
    graph.add_edge("vuln_scanner", "incident_response")
    graph.add_edge("incident_response", "policy_checker")
    graph.add_edge("policy_checker", END)
    return graph.compile()

def run_analysis(logs: list[str], log_source: str, session_id: str) -> SecurityState:
    app = build_graph()
    initial = make_initial_state(raw_logs=logs, log_source=log_source, session_id=session_id)
    try:
        result = app.invoke(initial)
        emit_sync(session_id, "pipeline", "done")
        return result
    finally:
        close_session(session_id)
```

- [ ] **Step 5: Run tests to verify they pass**

```bash
cd backend && .venv/bin/python -m pytest tests/test_orchestrator.py -v
```
Expected: PASS

- [ ] **Step 6: Run all backend tests**

```bash
cd backend && .venv/bin/python -m pytest tests/ -v
```
Expected: All PASS

- [ ] **Step 7: Commit**

```bash
git add backend/session_events.py backend/orchestrator.py backend/tests/test_orchestrator.py
git commit -m "feat: session event queues + LangGraph orchestrator with live SSE hooks"
```

---

## Task 9: FastAPI Backend — Async Analysis + Live SSE

**Files:**
- Create: `backend/main.py`
- Create: `backend/tests/test_api.py`

**Design:** `POST /analyze` returns `{ session_id }` immediately and starts LangGraph in a background thread. Agent wrappers push events to `session_events` queues. `GET /stream/{session_id}` reads the queue in real time. `GET /report/{session_id}` returns the final state once the background task finishes.

- [ ] **Step 1: Write failing API tests**

```python
# backend/tests/test_api.py
import asyncio
import json
from unittest.mock import patch
from fastapi.testclient import TestClient
from main import app

client = TestClient(app)

MOCK_STATE = {
    "raw_logs": [], "log_source": "synthetic", "session_id": "api-test",
    "anomalies": [{"type": "brute_force", "source_ip": "1.2.3.4", "severity": "CRITICAL"}],
    "severity_map": {"brute_force": "CRITICAL"},
    "cve_matches": [], "threat_score": 50,
    "vulnerabilities": [], "risk_level": "high",
    "action_plan": ["Block IP", "Rotate keys"],
    "runbook_md": "# Runbook\n1. Block IP",
    "compliance_gaps": [], "compliance_score": 80,
}

def test_analyze_returns_session_id_without_blocking():
    with patch("main._run_analysis_background") as mock_bg:
        response = client.post("/analyze", json={"source": "synthetic"})
    assert response.status_code == 200
    assert "session_id" in response.json()
    mock_bg.assert_called_once()

def test_report_returns_404_while_running():
    response = client.get("/report/not-a-real-session")
    assert response.status_code == 404

def test_report_returns_full_state_when_complete():
    from main import _sessions
    _sessions["done-session"] = MOCK_STATE
    response = client.get("/report/done-session")
    assert response.status_code == 200
    data = response.json()
    assert data["session_id"] == "api-test"
    assert "action_plan" in data
```

- [ ] **Step 2: Run tests to verify they fail**

```bash
cd backend && .venv/bin/python -m pytest tests/test_api.py -v
```
Expected: FAIL — `ModuleNotFoundError: No module named 'main'`

- [ ] **Step 3: Implement main.py**

```python
# backend/main.py
import asyncio
import json
import uuid
from pathlib import Path
from typing import AsyncGenerator

from fastapi import FastAPI, UploadFile, File, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from sse_starlette.sse import EventSourceResponse

from orchestrator import run_analysis
from session_events import create_session, get_queue, get_agent_status

app = FastAPI(title="CyberSentinel AI")
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_methods=["*"], allow_headers=["*"])

_sessions: dict[str, dict] = {}
_running: set[str] = set()

SYNTHETIC_LOGS_PATH = Path(__file__).parent / "data" / "synthetic_logs.json"

class AnalyzeRequest(BaseModel):
    source: str  # "synthetic" | "system"

def _load_synthetic_logs() -> list[str]:
    return json.loads(SYNTHETIC_LOGS_PATH.read_text())

def _load_system_logs() -> list[str]:
    logs = []
    for path in ["/var/log/auth.log", "/var/log/syslog"]:
        try:
            with open(path) as f:
                logs.extend(f.readlines()[-200:])
        except FileNotFoundError:
            pass
    return [l.strip() for l in logs if l.strip()] or _load_synthetic_logs()

async def _run_analysis_background(logs: list[str], log_source: str, session_id: str) -> None:
    _running.add(session_id)
    try:
        state = await asyncio.to_thread(run_analysis, logs, log_source, session_id)
        _sessions[session_id] = state
    finally:
        _running.discard(session_id)

def _start_analysis(logs: list[str], log_source: str) -> str:
    session_id = str(uuid.uuid4())
    create_session(session_id)
    asyncio.create_task(_run_analysis_background(logs, log_source, session_id))
    return session_id

@app.post("/analyze")
async def analyze(request: AnalyzeRequest):
    if request.source == "synthetic":
        logs = _load_synthetic_logs()
    elif request.source == "system":
        logs = _load_system_logs()
    else:
        raise HTTPException(status_code=400, detail="Use /analyze/upload for file uploads")
    session_id = _start_analysis(logs, request.source)
    return {"session_id": session_id}

@app.post("/analyze/upload")
async def analyze_upload(file: UploadFile = File(...)):
    content = await file.read()
    if len(content) > 10 * 1024 * 1024:
        raise HTTPException(status_code=400, detail="File too large (max 10MB)")
    if not (file.filename or "").endswith((".log", ".txt")):
        raise HTTPException(status_code=400, detail="Only .log and .txt files accepted")
    logs = content.decode("utf-8", errors="ignore").splitlines()
    session_id = _start_analysis(logs, "upload")
    return {"session_id": session_id}

@app.get("/stream/{session_id}")
async def stream(session_id: str):
    q = get_queue(session_id)
    if not q:
        raise HTTPException(status_code=404, detail="Session not found")

    async def event_generator() -> AsyncGenerator[dict, None]:
        while True:
            event = await asyncio.to_thread(q.get)
            if event is None:
                break
            yield {"data": json.dumps(event)}

    return EventSourceResponse(event_generator())

@app.get("/report/{session_id}")
async def get_report(session_id: str):
    state = _sessions.get(session_id)
    if not state:
        raise HTTPException(status_code=404, detail="Session not found or still running")
    return state

@app.get("/agents/status/{session_id}")
async def agents_status(session_id: str):
    status = get_agent_status(session_id)
    if not status:
        raise HTTPException(status_code=404, detail="Session not found")
    return status
```

- [ ] **Step 4: Run tests to verify they pass**

```bash
cd backend && .venv/bin/python -m pytest tests/test_api.py -v
```
Expected: 3 PASS

- [ ] **Step 5: Run all backend tests**

```bash
cd backend && .venv/bin/python -m pytest tests/ -v
```
Expected: All PASS

- [ ] **Step 6: Commit**

```bash
git add backend/main.py backend/tests/test_api.py
git commit -m "feat: async FastAPI backend with live SSE streaming"
```

---

## Task 10: Frontend — Types + useSSE Hook + App Shell

**Files:**
- Create: `frontend/src/types.ts`
- Create: `frontend/src/hooks/useSSE.ts`
- Create: `frontend/src/App.tsx`

- [ ] **Step 1: Create shared TypeScript types**

```typescript
// frontend/src/types.ts
export interface Anomaly {
  type: string;
  source_ip?: string;
  severity: string;
  attempt_count?: number;
  detail?: string;
}

export interface CVEMatch {
  id: string;
  description: string;
  cvss_score: number;
  linked_anomaly: string;
}

export interface Vulnerability {
  category?: string;
  name?: string;
  header?: string;
  severity: string;
  recommendation?: string;
}

export interface ComplianceGap {
  framework: string;
  control_id: string;
  description: string;
  severity: string;
}

export interface SecurityReport {
  session_id: string;
  anomalies: Anomaly[];
  cve_matches: CVEMatch[];
  vulnerabilities: Vulnerability[];
  risk_level: string;
  threat_score: number;
  action_plan: string[];
  runbook_md: string;
  compliance_gaps: ComplianceGap[];
  compliance_score: number;
}

export interface AgentEvent {
  agent: string;
  status: 'running' | 'done' | 'error';
  findings?: unknown[];
  timestamp: string;
}
```

- [ ] **Step 2: Implement useSSE hook**

```typescript
// frontend/src/hooks/useSSE.ts
import { useEffect, useRef, useState } from 'react';
import type { AgentEvent } from '../types';

export function useSSE(sessionId: string | null) {
  const [events, setEvents] = useState<AgentEvent[]>([]);
  const [done, setDone] = useState(false);
  const esRef = useRef<EventSource | null>(null);

  useEffect(() => {
    if (!sessionId) return;
    setEvents([]);
    setDone(false);

    const es = new EventSource(`http://localhost:8000/stream/${sessionId}`);
    esRef.current = es;

    es.onmessage = (e) => {
      try {
        const event: AgentEvent = JSON.parse(e.data);
        setEvents(prev => [...prev, event]);
        if (event.agent === 'pipeline' && event.status === 'done') {
          setDone(true);
          es.close();
        }
      } catch {}
    };

    es.onerror = () => { setDone(true); es.close(); };
    return () => es.close();
  }, [sessionId]);

  return { events, done };
}
```

- [ ] **Step 3: Implement App.tsx shell**

```typescript
// frontend/src/App.tsx
import { useEffect, useState } from 'react';
import type { SecurityReport } from './types';
import LogSourceSelector from './components/LogSourceSelector';
import MetricCard from './components/MetricCard';
import AgentFeed from './components/AgentFeed';
import IncidentReport from './components/IncidentReport';
import { useSSE } from './hooks/useSSE';

const API = 'http://localhost:8000';

export default function App() {
  const [sessionId, setSessionId] = useState<string | null>(null);
  const [report, setReport] = useState<SecurityReport | null>(null);
  const [loading, setLoading] = useState(false);
  const { events, done } = useSSE(sessionId);

  async function handleRunAnalysis(source: string, file?: File) {
    setLoading(true);
    setReport(null);
    setSessionId(null);
    let id: string;
    if (source === 'upload' && file) {
      const form = new FormData();
      form.append('file', file);
      const res = await fetch(`${API}/analyze/upload`, { method: 'POST', body: form });
      id = (await res.json()).session_id;
    } else {
      const res = await fetch(`${API}/analyze`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ source }),
      });
      id = (await res.json()).session_id;
    }
    setSessionId(id);
    setLoading(false);
  }

  useEffect(() => {
    if (!done || !sessionId || report) return;
    fetch(`${API}/report/${sessionId}`)
      .then(res => res.json())
      .then(setReport)
      .catch(() => setReport(null));
  }, [done, sessionId, report]);

  const criticalCount = report?.anomalies.filter(a => a.severity === 'CRITICAL').length ?? 0;
  const warningCount = report?.anomalies.filter(a => a.severity === 'HIGH').length ?? 0;
  const agentsActive = events.length;

  return (
    <div className="min-h-screen bg-gray-950 text-gray-100 font-sans">
      <nav className="flex items-center justify-between px-6 py-4 border-b border-gray-800">
        <span className="text-blue-400 font-bold text-lg">🛡️ CyberSentinel AI</span>
        <div className="flex gap-3 text-sm text-gray-400">
          <span className="px-3 py-1 bg-gray-800 rounded-md">Dashboard</span>
        </div>
      </nav>

      <main className="max-w-6xl mx-auto px-6 py-8 space-y-6">
        <LogSourceSelector onRun={handleRunAnalysis} loading={loading} />

        <div className="grid grid-cols-5 gap-4">
          <MetricCard label="Critical Threats" value={criticalCount} color="red" />
          <MetricCard label="Warnings" value={warningCount} color="yellow" />
          <MetricCard label="Agents Active" value={`${agentsActive}/5`} color="green" />
          <MetricCard label="Compliance Score" value={report ? `${report.compliance_score}%` : '—'} color="blue" />
          <MetricCard label="Risk Level" value={report?.risk_level.toUpperCase() ?? '—'} color="purple" />
        </div>

        <div className="grid grid-cols-2 gap-4">
          <AgentFeed events={events} />
          <IncidentReport report={report} />
        </div>
      </main>
    </div>
  );
}
```

- [ ] **Step 4: Verify TypeScript compiles**

```bash
cd frontend && npx tsc --noEmit
```
Expected: No errors (components don't exist yet — that's fine, we'll add them next)

- [ ] **Step 5: Commit**

```bash
git add frontend/src/types.ts frontend/src/hooks/useSSE.ts frontend/src/App.tsx
git commit -m "feat: frontend types, useSSE hook, App shell"
```

---

## Task 11: Frontend Components

**Files:**
- Create: `frontend/src/components/LogSourceSelector.tsx`
- Create: `frontend/src/components/MetricCard.tsx`
- Create: `frontend/src/components/AgentFeed.tsx`
- Create: `frontend/src/components/IncidentReport.tsx`

- [ ] **Step 1: Implement LogSourceSelector.tsx**

```typescript
// frontend/src/components/LogSourceSelector.tsx
import { useRef, useState } from 'react';

interface Props {
  onRun: (source: string, file?: File) => void;
  loading: boolean;
}

export default function LogSourceSelector({ onRun, loading }: Props) {
  const [source, setSource] = useState('synthetic');
  const [file, setFile] = useState<File | null>(null);
  const inputRef = useRef<HTMLInputElement>(null);

  return (
    <div className="bg-gray-900 border border-gray-800 rounded-xl p-4 flex flex-wrap items-center gap-3">
      <span className="text-gray-400 text-xs uppercase tracking-widest">Log Source</span>
      {['synthetic', 'system', 'upload'].map(s => (
        <button
          key={s}
          onClick={() => { setSource(s); if (s === 'upload') inputRef.current?.click(); }}
          className={`px-4 py-1.5 rounded-md text-sm transition-colors ${
            source === s ? 'bg-blue-900 border border-blue-500 text-blue-300' : 'bg-gray-800 text-gray-400 hover:bg-gray-700'
          }`}
        >
          {s === 'synthetic' ? '⚡ Synthetic' : s === 'system' ? '🖥️ System Logs' : '📁 Upload File'}
        </button>
      ))}
      <input
        ref={inputRef}
        type="file"
        accept=".log,.txt"
        className="hidden"
        onChange={e => setFile(e.target.files?.[0] ?? null)}
      />
      {file && <span className="text-xs text-gray-400">{file.name}</span>}
      <button
        onClick={() => onRun(source, file ?? undefined)}
        disabled={loading || (source === 'upload' && !file)}
        className="ml-auto px-5 py-1.5 bg-red-600 hover:bg-red-500 disabled:bg-gray-700 disabled:text-gray-500 text-white text-sm font-bold rounded-md transition-colors"
      >
        {loading ? '⏳ Analyzing...' : '▶ Run Analysis'}
      </button>
    </div>
  );
}
```

- [ ] **Step 2: Implement MetricCard.tsx**

```typescript
// frontend/src/components/MetricCard.tsx
const COLOR_MAP: Record<string, string> = {
  red:    'border-red-800 bg-red-950 text-red-400',
  yellow: 'border-yellow-800 bg-yellow-950 text-yellow-400',
  green:  'border-green-800 bg-green-950 text-green-400',
  blue:   'border-blue-800 bg-blue-950 text-blue-400',
  purple: 'border-purple-800 bg-purple-950 text-purple-400',
};

interface Props { label: string; value: string | number; color: string; }

export default function MetricCard({ label, value, color }: Props) {
  return (
    <div className={`border rounded-xl p-4 ${COLOR_MAP[color] ?? COLOR_MAP.blue}`}>
      <div className="text-2xl font-bold">{value}</div>
      <div className="text-gray-400 text-xs mt-1">{label}</div>
    </div>
  );
}
```

- [ ] **Step 3: Implement AgentFeed.tsx**

```typescript
// frontend/src/components/AgentFeed.tsx
import type { AgentEvent } from '../types';

const AGENT_COLORS: Record<string, string> = {
  log_monitor:       'text-green-400',
  threat_intel:      'text-red-400',
  vuln_scanner:      'text-purple-400',
  incident_response: 'text-yellow-400',
  policy_checker:    'text-cyan-400',
};

const AGENT_LABELS: Record<string, string> = {
  log_monitor:       'LogMonitor',
  threat_intel:      'ThreatIntel',
  vuln_scanner:      'VulnScanner',
  incident_response: 'IncidentResponse',
  policy_checker:    'PolicyChecker',
};

interface Props { events: AgentEvent[]; }

export default function AgentFeed({ events }: Props) {
  return (
    <div className="bg-gray-900 border border-gray-800 rounded-xl p-4">
      <h3 className="text-gray-400 text-xs uppercase tracking-widest mb-3">Agent Activity</h3>
      {events.length === 0 && (
        <p className="text-gray-600 text-sm">Waiting for analysis to start...</p>
      )}
      <div className="space-y-2">
        {events.map((e, i) => (
          <div key={i} className="flex gap-2 text-sm">
            <span className={`${AGENT_COLORS[e.agent] ?? 'text-gray-400'} font-medium`}>
              ● {AGENT_LABELS[e.agent] ?? e.agent}
            </span>
            <span className="text-gray-500">
              {e.status === 'running' ? 'analyzing...' : e.status === 'done' ? 'complete' : 'error'}
            </span>
          </div>
        ))}
      </div>
    </div>
  );
}
```

- [ ] **Step 4: Implement IncidentReport.tsx**

```typescript
// frontend/src/components/IncidentReport.tsx
import type { SecurityReport } from '../types';

interface Props { report: SecurityReport | null; }

export default function IncidentReport({ report }: Props) {
  function downloadReport() {
    if (!report) return;
    const blob = new Blob([JSON.stringify(report, null, 2)], { type: 'application/json' });
    const a = document.createElement('a');
    a.href = URL.createObjectURL(blob);
    a.download = `cybersentinel-report-${report.session_id}.json`;
    a.click();
  }

  return (
    <div className="bg-gray-900 border border-gray-800 rounded-xl p-4">
      <div className="flex items-center justify-between mb-3">
        <h3 className="text-gray-400 text-xs uppercase tracking-widest">Incident Report</h3>
        {report && (
          <button onClick={downloadReport} className="text-xs bg-blue-900 text-blue-300 px-3 py-1 rounded-md hover:bg-blue-800">
            ⬇ Download
          </button>
        )}
      </div>

      {!report && <p className="text-gray-600 text-sm">Report will appear after analysis completes.</p>}

      {report && (
        <div className="space-y-4">
          <div>
            <h4 className="text-yellow-400 font-semibold text-sm mb-2">🚨 Action Plan</h4>
            <ol className="space-y-1 text-sm text-gray-300">
              {report.action_plan.map((step, i) => (
                <li key={i}>{i + 1}. {step}</li>
              ))}
            </ol>
          </div>
          <div className="pt-3 border-t border-gray-800">
            <h4 className="text-cyan-400 font-semibold text-sm mb-2">📜 Compliance Gaps</h4>
            <div className="text-xs text-gray-400 space-y-1">
              {report.compliance_gaps.slice(0, 6).map((g, i) => (
                <div key={i}>{g.framework} · {g.control_id} — {g.description}</div>
              ))}
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
```

- [ ] **Step 5: Verify TypeScript compiles cleanly**

```bash
cd frontend && npx tsc --noEmit
```
Expected: No errors

- [ ] **Step 6: Start dev server and verify UI renders**

```bash
cd frontend && npm run dev
```
Open http://localhost:5173 — should show dark dashboard with log source selector and metric cards.

- [ ] **Step 7: Commit**

```bash
git add frontend/src/components/
git commit -m "feat: dashboard components — LogSourceSelector, MetricCard, AgentFeed, IncidentReport"
```

---

## Task 12: End-to-End Demo Test

**Files:** none (manual verification)

- [ ] **Step 1: Run full backend test suite**

```bash
cd backend && .venv/bin/python -m pytest tests/ -v
```
Expected: All PASS

- [ ] **Step 2: Start backend and frontend together**

Terminal 1:
```bash
cd backend && source .venv/bin/activate && uvicorn main:app --reload --port 8000
```
Terminal 2:
```bash
cd frontend && npm run dev
```

- [ ] **Step 3: End-to-end smoke test**

1. Open http://localhost:5173
2. Click **⚡ Synthetic** then **▶ Run Analysis**
3. Verify agent feed shows each agent as `running` then `complete` **while** analysis is in progress (not all at once after a long wait)
4. Verify metric cards populate after the pipeline finishes
5. Verify incident report panel shows action plan and compliance gaps
6. Click **⬇ Download** and verify JSON file downloads (includes `session_id`)

- [ ] **Step 4: Verify cache benchmark still works**

```bash
cd backend && .venv/bin/python benchmark.py --dry-run --model openai/gpt-4o-mini
```
Expected: Cached pass shows 100% hit rate and zero cost.

- [ ] **Step 5: Commit** *(only if smoke-test fixes were needed)*

```bash
git commit -m "chore: verify end-to-end demo flow"
```

---

## Task 13: Final Polish + .gitignore

**Files:**
- Create: `.gitignore`
- Create: `backend/data/synthetic_logs.json` (already done in Task 2)

- [ ] **Step 1: Create .gitignore**

```
# .gitignore
backend/.venv/
backend/venv/
backend/__pycache__/
backend/.env
frontend/node_modules/
frontend/dist/
.env
.superpowers/
*.pyc
```

- [ ] **Step 2: Verify no secrets are tracked**

```bash
git status
```
Expected: `.env` and `.venv/` not listed.

- [ ] **Step 3: Final commit**

```bash
git add .gitignore
git commit -m "chore: add .gitignore"
```
