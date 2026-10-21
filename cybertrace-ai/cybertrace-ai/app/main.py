from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
from typing import Any
import random
import uuid

from fastapi import FastAPI, HTTPException
from fastapi.responses import HTMLResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

ROOT = Path(__file__).resolve().parent.parent
app = FastAPI(title="CyberTrace AI", version="1.0.0", description="Simulation-only cyber-physical attack localization prototype")
app.mount("/static", StaticFiles(directory=ROOT / "static"), name="static")

COMPONENTS = [
    {"id": "sensor", "label": "Sensor Node", "kind": "sensor", "description": "Battery voltage, current and temperature telemetry"},
    {"id": "gateway", "label": "Comms Gateway", "kind": "network", "description": "EV network message relay and validation"},
    {"id": "controller", "label": "Charge Controller", "kind": "controller", "description": "Charging logic and command generation"},
    {"id": "firmware", "label": "Firmware Monitor", "kind": "firmware", "description": "Signed-version and integrity status"},
    {"id": "actuator", "label": "Charger Actuator", "kind": "actuator", "description": "Simulated power output / contactor state"},
]
EDGES = [
    {"from": "sensor", "to": "gateway"},
    {"from": "gateway", "to": "controller"},
    {"from": "firmware", "to": "controller"},
    {"from": "controller", "to": "actuator"},
]

SCENARIOS: dict[str, dict[str, Any]] = {
    "sensor_spoofing": {
        "name": "Sensor spoofing", "description": "Telemetry values conflict with independent physical signals.", "origin": "sensor", "severity": "HIGH",
        "events": [
            ("sensor", "telemetry_outlier", "Battery temperature jumped 18°C in one sample; rate-of-change check failed.", "high"),
            ("gateway", "message_valid", "Telemetry packet passed format and authentication checks.", "info"),
            ("controller", "cross_signal_mismatch", "Temperature trend conflicts with current and voltage behavior.", "high"),
            ("actuator", "safe_limit_requested", "Controller requested conservative charging output after consistency check.", "medium"),
        ],
        "evidence": {"sensor": 0.92, "gateway": 0.25, "controller": 0.42, "firmware": 0.08, "actuator": 0.12},
        "path": ["sensor", "gateway", "controller", "actuator"],
        "impact": "Potentially misleading battery-state estimate; charging output is held in a simulated safe state.",
        "recommendations": ["Cross-check sensor values against independent telemetry.", "Mark sensor S-01 for inspection and preserve raw event records.", "Keep the simulated charger in conservative mode until readings agree."],
    },
    "gateway_tampering": {
        "name": "Communication manipulation", "description": "Message sequence and payload integrity checks show gateway anomalies.", "origin": "gateway", "severity": "HIGH",
        "events": [
            ("sensor", "telemetry_normal", "Sensor values remain within expected operating envelope.", "info"),
            ("gateway", "sequence_replay", "Repeated command sequence number detected at communication gateway.", "high"),
            ("gateway", "payload_mismatch", "Forwarded payload differs from the locally observed message digest.", "high"),
            ("controller", "command_guard", "Controller rejected stale command and requested fresh telemetry.", "medium"),
        ],
        "evidence": {"sensor": 0.12, "gateway": 0.95, "controller": 0.38, "firmware": 0.12, "actuator": 0.08},
        "path": ["gateway", "controller"],
        "impact": "A replayed or modified message could influence charging decisions if validation were absent.",
        "recommendations": ["Quarantine the suspicious gateway session in the simulator.", "Rotate test credentials and verify message sequence protection.", "Compare received payload digests with trusted sender records."],
    },
    "controller_compromise": {
        "name": "Controller command anomaly", "description": "Control output is inconsistent with validated input and safety policy.", "origin": "controller", "severity": "CRITICAL",
        "events": [
            ("sensor", "telemetry_normal", "Voltage, current and temperature telemetry are internally consistent.", "info"),
            ("gateway", "traffic_normal", "No message-integrity or replay indicators observed.", "info"),
            ("controller", "policy_violation", "Controller requested a power level above the configured simulation safety envelope.", "critical"),
            ("actuator", "output_divergence", "Requested actuator state differs from safe policy expectation.", "critical"),
        ],
        "evidence": {"sensor": 0.08, "gateway": 0.14, "controller": 0.96, "firmware": 0.35, "actuator": 0.48},
        "path": ["controller", "actuator"],
        "impact": "Unsafe charging command could create excessive electrical or thermal stress in a real system.",
        "recommendations": ["Reject the command in the simulation and place output in safe state.", "Review controller policy, access logs and recent configuration changes.", "Require an independent authorization check before resuming operation."],
    },
    "firmware_tampering": {
        "name": "Firmware integrity anomaly", "description": "Firmware integrity metadata no longer matches the trusted baseline.", "origin": "firmware", "severity": "CRITICAL",
        "events": [
            ("firmware", "integrity_mismatch", "Firmware hash differs from the approved reference baseline.", "critical"),
            ("firmware", "signature_status", "Expected signed-release metadata is missing in the simulated device report.", "high"),
            ("controller", "version_drift", "Controller reports an unexpected firmware build identifier.", "high"),
            ("actuator", "output_held", "Simulated output remains disabled pending integrity review.", "medium"),
        ],
        "evidence": {"sensor": 0.06, "gateway": 0.18, "controller": 0.40, "firmware": 0.97, "actuator": 0.16},
        "path": ["firmware", "controller", "actuator"],
        "impact": "Untrusted software could alter control behavior; no real firmware is modified by this prototype.",
        "recommendations": ["Keep the simulated device isolated from control operations.", "Verify the firmware against a trusted signed release.", "Review deployment history and restore only from a verified image."],
    },
    "actuator_fault": {
        "name": "Actuator response mismatch", "description": "Observed output does not match a valid controller request.", "origin": "actuator", "severity": "MEDIUM",
        "events": [
            ("sensor", "telemetry_normal", "Sensor telemetry is stable.", "info"),
            ("gateway", "traffic_normal", "No communication anomaly detected.", "info"),
            ("controller", "command_valid", "Controller command is within the configured simulation envelope.", "info"),
            ("actuator", "response_mismatch", "Actuator feedback does not match the requested state.", "high"),
        ],
        "evidence": {"sensor": 0.07, "gateway": 0.08, "controller": 0.15, "firmware": 0.10, "actuator": 0.88},
        "path": ["controller", "actuator"],
        "impact": "Charging delivery may be interrupted; this may be a component fault rather than a cyberattack.",
        "recommendations": ["Keep the simulated output disabled until feedback is consistent.", "Inspect actuator feedback and command timestamps.", "Classify as a possible fault unless additional cyber evidence appears."],
    },
}

state: dict[str, Any] = {"events": [], "incidents": [], "counter": 0, "started_at": datetime.now(timezone.utc).isoformat()}


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def add_event(component: str, event_type: str, message: str, severity: str = "info", incident_id: str | None = None) -> dict[str, Any]:
    item = {"id": str(uuid.uuid4())[:8], "timestamp": now_iso(), "component": component, "event_type": event_type, "message": message, "severity": severity, "incident_id": incident_id}
    state["events"].insert(0, item)
    state["events"] = state["events"][:150]
    return item


def create_incident(scenario_key: str) -> dict[str, Any]:
    scenario = SCENARIOS[scenario_key]
    state["counter"] += 1
    incident_id = f"CT-{state['counter']:03d}"
    # Evidence scores are illustrative localization likelihoods, not calibrated probabilities.
    scores = scenario["evidence"]
    ranked = sorted(scores.items(), key=lambda pair: pair[1], reverse=True)
    confidence = round(ranked[0][1], 2)
    alternatives = [{"component": key, "label": next(c["label"] for c in COMPONENTS if c["id"] == key), "score": round(value, 2)} for key, value in ranked]
    for component, event_type, message, severity in scenario["events"]:
        add_event(component, event_type, message, severity, incident_id)
    incident = {
        "id": incident_id, "created_at": now_iso(), "scenario": scenario_key, "name": scenario["name"],
        "description": scenario["description"], "severity": scenario["severity"], "status": "INVESTIGATING",
        "suspected_origin": scenario["origin"], "origin_label": next(c["label"] for c in COMPONENTS if c["id"] == scenario["origin"]),
        "confidence": confidence, "alternatives": alternatives, "path": scenario["path"],
        "impact": scenario["impact"], "recommendations": scenario["recommendations"],
        "evidence_summary": [e[2] for e in scenario["events"] if e[3] in ("high", "critical")],
        "method_note": "Ranked from predefined evidence weights in this educational simulation; scores are not calibrated probabilities.",
    }
    state["incidents"].insert(0, incident)
    state["incidents"] = state["incidents"][:50]
    return incident


@app.get("/", response_class=HTMLResponse)
def home() -> str:
    return (ROOT / "static" / "index.html").read_text(encoding="utf-8")


@app.get("/api/health")
def health() -> dict[str, Any]:
    return {"status": "ok", "app": "CyberTrace AI", "mode": "SIMULATION ONLY", "time": now_iso()}


@app.get("/api/topology")
def topology() -> dict[str, Any]:
    latest = state["incidents"][0] if state["incidents"] else None
    scores = latest["alternatives"] if latest else []
    score_map = {item["component"]: item["score"] for item in scores}
    path = latest["path"] if latest else []
    components = []
    for c in COMPONENTS:
        components.append({**c, "score": score_map.get(c["id"], 0), "on_path": c["id"] in path, "suspected": bool(latest and c["id"] == latest["suspected_origin"])})
    return {"components": components, "edges": EDGES, "active_incident": latest["id"] if latest else None}


@app.get("/api/summary")
def summary() -> dict[str, Any]:
    return {"events_total": len(state["events"]), "incidents_total": len(state["incidents"]), "high_risk": sum(1 for i in state["incidents"] if i["severity"] in ("HIGH", "CRITICAL") and i["status"] != "RESOLVED"), "last_event": state["events"][0]["timestamp"] if state["events"] else None, "mode": "SIMULATION ONLY"}


@app.get("/api/events")
def events(limit: int = 30) -> dict[str, Any]:
    return {"items": state["events"][:max(1, min(limit, 100))]}


@app.get("/api/incidents")
def incidents() -> dict[str, Any]:
    return {"items": state["incidents"]}


class SimulateRequest(BaseModel):
    scenario: str


@app.post("/api/simulate")
def simulate(body: SimulateRequest) -> dict[str, Any]:
    if body.scenario not in SCENARIOS:
        raise HTTPException(status_code=400, detail=f"Unknown scenario. Choose one of: {', '.join(SCENARIOS)}")
    return {"incident": create_incident(body.scenario), "summary": summary()}


@app.post("/api/simulate/normal")
def simulate_normal() -> dict[str, Any]:
    normal_events = [
        ("sensor", "telemetry_normal", "Battery telemetry within expected envelope.", "info"),
        ("gateway", "traffic_normal", "Gateway traffic and message sequence checks passed.", "info"),
        ("controller", "command_valid", "Charging command complies with simulated safety policy.", "info"),
        ("actuator", "output_normal", "Simulated actuator feedback matches requested state.", "info"),
        ("firmware", "integrity_ok", "Firmware baseline integrity check passed.", "info"),
    ]
    for component, event_type, message, severity in normal_events:
        add_event(component, event_type, message, severity)
    return {"message": "Normal operating telemetry added.", "summary": summary()}


@app.post("/api/incidents/{incident_id}/resolve")
def resolve_incident(incident_id: str) -> dict[str, Any]:
    for incident in state["incidents"]:
        if incident["id"] == incident_id:
            incident["status"] = "RESOLVED"
            add_event("controller", "incident_resolved", f"Incident {incident_id} marked resolved by dashboard operator.", "info", incident_id)
            return {"incident": incident}
    raise HTTPException(status_code=404, detail="Incident not found")


@app.post("/api/reset")
def reset() -> dict[str, str]:
    state["events"].clear()
    state["incidents"].clear()
    state["counter"] = 0
    return {"message": "Simulation state reset."}
