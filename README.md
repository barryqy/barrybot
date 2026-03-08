# BarryBot

BarryBot is the standalone Cisco AI Defense demo backend that powers the `agentsec` and `agentsec-local` pages on `barrysecure.com`.

The repo contains:

- `barrybot.py`: the LangChain LLM demo
- `barrybot_mcp.py`: the MCP demo
- `flight_mcp_server.py`: the malicious MCP server used by the MCP demo
- `backend/app.py`: the Flask API on port `5001`
- `.reference/ai-defense-python-sdk-agentsec-changes/`: the vendored SDK branch used by the demo runtime

## Local run

```bash
python3 -m venv venv
source venv/bin/activate
pip install --upgrade pip
pip install -r backend/requirements.txt
cp .env.example .env
python3 backend/app.py
```

The backend reads `.env` from the repo root and serves:

- `GET /api/health`
- `GET /api/source`
- `GET /api/artifact`
- `POST /api/run`

## Production update model

This repo is intended to be the source of truth for the AWS instance. The server can clone it once, then periodically run:

```bash
deploy/pull-latest.sh
```

That script:

1. pulls the latest `main`
2. refreshes Python dependencies
3. reinstalls the systemd units from this repo
4. restarts `agentsec-backend` only when the repo changed

## Server bootstrap

On the EC2 instance:

```bash
git clone https://github.com/barryqy/barrybot.git /home/ubuntu/barrybot
cd /home/ubuntu/barrybot
sudo deploy/bootstrap-server.sh
```

If an older deploy already exists at `/home/ubuntu/agentsec/.env`, the bootstrap script copies that `.env` into the new repo automatically.
