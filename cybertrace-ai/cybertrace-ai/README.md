# CyberTrace AI — AI-07 Attack Localization Prototype

CyberTrace AI is a local, simulation-only web application for demonstrating evidence-based attack-source localization in a connected EV charging system. It is designed around AI-07: **The Attack-Localization Problem**.

## What it does

- Displays a cyber-physical topology containing a sensor, communication gateway, charge controller, firmware monitor, and charger actuator.
- Adds synthetic normal telemetry or triggers one of five repeatable scenarios.
- Ranks likely origin components using scenario evidence weights.
- Displays a suspected propagation path, event evidence, impact notes, and response recommendations.
- Tracks incidents, supports marking an incident resolved, and allows resetting the demo state.
- Exposes a small FastAPI JSON API.

## Safety and scope

This is an educational proof of concept, not a production security product. All scenario data is synthetic and stored in memory. No real EV, charger, firmware, network interface, or actuator is accessed or controlled. The displayed evidence scores are illustrative weights—not calibrated probabilities—and the scenarios use predefined evidence profiles rather than a trained ML model. Do not present them as validated real-world detection accuracy.

## Requirements

- Python 3.10 or newer
- pip
- A modern browser

## Run locally

### Windows (PowerShell)

```powershell
cd cybertrace-ai
py -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
uvicorn app.main:app --reload
```

If PowerShell blocks virtual-environment activation, use `\.venv\Scripts\python.exe -m pip install -r requirements.txt` and then `\.venv\Scripts\python.exe -m uvicorn app.main:app --reload`.

### macOS / Linux

```bash
cd cybertrace-ai
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -r requirements.txt
uvicorn app.main:app --reload
```

Open **http://127.0.0.1:8000**. Interactive API docs are at **http://127.0.0.1:8000/docs**.

## Demo flow for judges

1. Open the dashboard; it should show an empty incident queue.
2. Click **Add normal telemetry** to show baseline events.
3. Trigger **Sensor spoofing** and inspect the suspected source, evidence score, event stream, and path.
4. Trigger **Communication manipulation** and compare the source hypothesis and propagation path.
5. Trigger **Controller command anomaly** or **Firmware integrity anomaly** to demonstrate cross-layer localization.
6. Expand an incident and explain its evidence and recommended response.
7. Mark an incident resolved, then use **Reset demo** to clear the in-memory session.

## API endpoints

| Method | Endpoint | Purpose |
|---|---|---|
| GET | `/api/health` | Health and simulation mode |
| GET | `/api/summary` | Dashboard counters |
| GET | `/api/topology` | Components, edges, current source scores |
| GET | `/api/events?limit=35` | Recent synthetic events |
| GET | `/api/incidents` | Incident investigations |
| POST | `/api/simulate` | Trigger a scenario, body `{"scenario":"sensor_spoofing"}` |
| POST | `/api/simulate/normal` | Add normal telemetry events |
| POST | `/api/incidents/{incident_id}/resolve` | Mark an incident resolved |
| POST | `/api/reset` | Clear in-memory simulation state |

Scenario keys: `sensor_spoofing`, `gateway_tampering`, `controller_compromise`, `firmware_tampering`, `actuator_fault`.

## Project structure

```text
cybertrace-ai/
├── app/
│   ├── __init__.py
│   └── main.py
├── static/
│   ├── index.html
│   ├── styles.css
│   └── app.js
├── requirements.txt
└── README.md
```

## Suggested next steps

For a stronger research prototype, replace the predefined evidence profiles with a labeled dataset and a documented localization model. Evaluate component-level top-1 accuracy, precision/recall, false-positive rate, localization latency, and path reconstruction accuracy on held-out scenarios. Add signed event ingestion, authentication, persistent storage, and role-based access control before any non-demo use.
