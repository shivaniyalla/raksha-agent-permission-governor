
# RAKSHA — Agent Permission Governor

RAKSHA is an AI Agent Permission Governor designed to control and evaluate actions requested by AI agents before execution.

## Key Features

- Risk-based action evaluation
- ALLOW, DENY, and HUMAN_APPROVAL decisions
- Prompt-injection detection
- Permission and policy enforcement
- Action provenance and audit logging
- Health and metrics monitoring
- Authorized execution controls
- Payload-size protection

## Project Structure

- `app.py` — Application entry point
- `governor.py` — Core permission governor
- `permission_engine.py` — Permission evaluation
- `policy_engine.py` — Policy enforcement
- `risk_engine.py` — Risk assessment
- `injection_detector.py` — Prompt-injection detection
- `approval.py` — Human approval workflow
- `executor.py` — Action execution
- `audit.py` — Audit logging
- `provenance.py` — Action provenance
- `tests/` — Automated tests

## Installation

Use Python 3.13 if compatible with the project's dependencies, or the Python version specified by the project.

```bash
git clone https://github.com/shivaniyalla/raksha-agent-permission-governor.git
cd raksha-agent-permission-governor
python -m venv .venv
```

Activate the environment, then install dependencies:

Windows:

```powershell
.venv\Scripts\Activate.ps1
pip install -r requirements.txt
```

## Run

Check the application's entry point and run the appropriate command. If `app.py` uses Streamlit:

```bash
streamlit run app.py
```

## Security

Never commit API keys, passwords, access tokens, or private data.

## Team

Team DURJAYA

## Status

Hackathon project — under development.
