import queue
from datetime import datetime, timezone

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


def emit_sync(
    session_id: str, agent: str, status: str, findings: list | None = None
) -> None:
    q = _queues.get(session_id)
    if not q:
        return
    if agent in _status.get(session_id, {}):
        _status[session_id][agent] = status
    q.put(
        {
            "agent": agent,
            "status": status,
            "findings": findings or [],
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }
    )


def close_session(session_id: str) -> None:
    q = _queues.get(session_id)
    if q:
        q.put(None)
