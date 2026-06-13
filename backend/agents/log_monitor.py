from state import SecurityState
from tools.log_parser import detect_anomalies, parse_log_line


def run_log_monitor(state: SecurityState) -> SecurityState:
    events = [parse_log_line(line) for line in state["raw_logs"]]
    anomalies = detect_anomalies(events)
    severity_map = {a["type"]: a["severity"] for a in anomalies}
    return {**state, "anomalies": anomalies, "severity_map": severity_map}
