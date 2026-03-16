"""
Flask API for agentsec conference demo.
Serves /api/health, /api/run (runs barrybot.py subprocesses), /api/source.
"""

import os
import json
import subprocess
import uuid
import importlib.util
import base64
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor, as_completed
from functools import lru_cache
from urllib.error import HTTPError, URLError
from urllib.parse import urlencode
from urllib.request import Request, urlopen

from dotenv import dotenv_values, load_dotenv
from flask import Flask, request, jsonify
from flask_cors import CORS

# Agent directory: parent of backend/ (contains demo scripts, users.db, artifacts)
BACKEND_DIR = Path(__file__).resolve().parent
AGENT_DIR = BACKEND_DIR.parent
MIDDLEWARE_DIR = Path(
    os.environ.get(
        "LANGCHAIN_MIDDLEWARE_DIR",
        str(Path.home() / "code" / "ai-defense-langchain-middleware-personal"),
    )
)
ENV_PATH = AGENT_DIR / ".env"
# Load .env from agent dir so local debugging still works in this Flask process.
load_dotenv(ENV_PATH, override=True)


def corsOrigins() -> list[str]:
    configured = os.environ.get("AI_DEFENSE_ALLOWED_ORIGINS", "")
    if configured.strip():
        values = []
        for raw_item in configured.split(","):
            item = raw_item.strip()
            if item:
                values.append(item)
        if values:
            return values

    return [
        "https://barrysecure.com",
        "https://aidefense-dev-portal.vercel.app",
        "http://localhost:4321",
        "http://127.0.0.1:4321",
        "http://localhost:4173",
        "http://127.0.0.1:4173",
    ]


app = Flask(__name__)
CORS(app, origins=corsOrigins())

# PYTHONPATH: use cloned ai-defense-python-sdk (commit 12acfba) when present, else AGENT_DIR
SDK_ROOT = AGENT_DIR / ".reference" / "ai-defense-python-sdk-agentsec-changes"
REPO_ROOT = SDK_ROOT if SDK_ROOT.exists() else AGENT_DIR
RUN_SCRIPT_FILES = {
    "barrybot.py": AGENT_DIR / "barrybot.py",
    "barrybot_middleware.py": AGENT_DIR / "barrybot_middleware.py",
    "barrybot_mcp.py": AGENT_DIR / "barrybot_mcp.py",
}
SOURCE_FILES = {
    **RUN_SCRIPT_FILES,
    "flight_mcp_server.py": AGENT_DIR / "flight_mcp_server.py",
}
ARTIFACT_DIR = AGENT_DIR / ".artifacts"
ARTIFACT_DIR.mkdir(exist_ok=True)
LOCAL_SESSION_CACHE = AGENT_DIR.parent / "DevNet" / "aidefense" / "aidefense" / "session_cache.py"
LOCAL_SESSION_CACHE_FILE = LOCAL_SESSION_CACHE.parent / ".aidefense" / ".cache"


def _resolve_run_script(script_name: str) -> Path:
    script_path = RUN_SCRIPT_FILES.get(script_name or "barrybot.py")
    if not script_path:
        raise ValueError(f"Unsupported script: {script_name}")
    if not script_path.exists():
        raise FileNotFoundError(f"{script_path.name} not found")
    return script_path


def _resolve_source_script(script_name: str) -> Path:
    script_path = SOURCE_FILES.get(script_name or "barrybot.py")
    if not script_path:
        raise ValueError(f"Unsupported script: {script_name}")
    if not script_path.exists():
        raise FileNotFoundError(f"{script_path.name} not found")
    return script_path


def _resolve_artifact(artifact_id: str) -> Path:
    if not artifact_id:
        raise ValueError("artifact id is required")
    safe_name = Path(artifact_id).name
    if safe_name != artifact_id or not safe_name.endswith(".data.md"):
        raise ValueError(f"Unsupported artifact id: {artifact_id}")
    return ARTIFACT_DIR / safe_name


def _short_error_from_stderr(stderr: str) -> str:
    """Extract a short error message from subprocess stderr (avoid dumping full DEBUG logs)."""
    if not stderr or not stderr.strip():
        return "Subprocess failed"
    lines = stderr.strip().splitlines()
    # Prefer last line that looks like an exception (e.g. "openai.UnprocessableEntityError: ...")
    for line in reversed(lines):
        line = line.strip()
        if line.startswith(("Error", "error", "Exception", "Traceback")) or "Error:" in line or "Exception:" in line:
            return line[:500]
    # Otherwise last non-empty line
    for line in reversed(lines):
        if line.strip() and not line.strip().startswith("["):
            return line.strip()[:500]
    return lines[-1].strip()[:500] if lines else "Subprocess failed"


def _collect_logs(*streams: str) -> list[str]:
    """Keep non-empty stdout/stderr payloads so the UI can show raw failure context."""
    return [stream for stream in streams if stream and stream.strip()]


def _subprocess_env() -> dict[str, str]:
    """Build subprocess env from current process env plus the latest .env values on disk."""
    env = {**os.environ}
    env.update({key: value for key, value in dotenv_values(ENV_PATH).items() if value is not None})
    env["PYTHONPATH"] = str(REPO_ROOT)
    return env


def _middleware_python_exe(env: dict[str, str]) -> str:
    runtime_python = MIDDLEWARE_DIR / ".venv" / "bin" / "python"
    if runtime_python.exists():
        return str(runtime_python)
    return env.get("PYTHON_EXE", "python3")


def _artifact_env(script_name: str, mode: str, run_id: str) -> dict[str, str]:
    if script_name != "barrybot_mcp.py":
        return {}
    artifact_id = f"{run_id}-{mode}.data.md"
    artifact_path = _resolve_artifact(artifact_id)
    artifact_path.parent.mkdir(parents=True, exist_ok=True)
    if artifact_path.exists():
        artifact_path.unlink()
    return {
        "BARRYBOT_EXFIL_ID": artifact_id,
        "BARRYBOT_EXFIL_PATH": str(artifact_path),
    }


@lru_cache(maxsize=1)
def _management_api_key() -> str | None:
    for name in (
        "AI_DEFENSE_MGMT_API_KEY",
        "AI_DEFENSE_MANAGEMENT_API_KEY",
        "AI_DEFENSE_MGMT_API",
    ):
        value = os.environ.get(name)
        if value:
            return value

    if LOCAL_SESSION_CACHE_FILE.exists():
        try:
            token = None
            for line in LOCAL_SESSION_CACHE_FILE.read_text().splitlines():
                line = line.strip()
                if line.startswith("session_token="):
                    token = line.split("=", 1)[1].strip()
                    break
            if token:
                data = base64.b64decode(token)
                env_key = os.environ.get("DEVENV_USER", "default-key-fallback")
                repeated_key = (env_key * (len(data) // len(env_key) + 1))[: len(data)]
                plaintext = bytes(a ^ b for a, b in zip(data, repeated_key.encode())).decode("utf-8")
                parts = plaintext.split(":")
                if len(parts) > 4 and parts[4] and parts[4] != "none":
                    return parts[4]
        except Exception:
            pass

    if LOCAL_SESSION_CACHE.exists():
        try:
            spec = importlib.util.spec_from_file_location("agentsec_session_cache", LOCAL_SESSION_CACHE)
            if spec and spec.loader:
                module = importlib.util.module_from_spec(spec)
                spec.loader.exec_module(module)
                getter = getattr(module, "get_mgmt_api", None)
                if getter:
                    value = getter()
                    if value:
                        return value
        except Exception:
            pass

    return None


def _fetch_event_log(event_id: str | None) -> list[str]:
    if not event_id:
        return []
    api_key = _management_api_key()
    if not api_key:
        return [f"[aidefense] Event ID: {event_id}"]

    url = f"https://api.security.cisco.com/api/ai-defense/v1/events/{event_id}?{urlencode({'expanded': 'true'})}"
    req = Request(url, headers={"X-Cisco-AI-Defense-Tenant-API-Key": api_key})
    try:
        with urlopen(req, timeout=30) as response:
            payload = json.loads(response.read().decode("utf-8"))
    except (HTTPError, URLError, TimeoutError, json.JSONDecodeError):
        return [f"[aidefense] Event ID: {event_id}"]

    event = payload.get("event") or {}
    if not event:
        return [f"[aidefense] Event ID: {event_id}"]

    lines = [f"[aidefense] Event ID: {event.get('event_id', event_id)}"]
    if event.get("direction"):
        lines.append(f"[aidefense] Direction: {event['direction']}")
    if event.get("event_action"):
        lines.append(f"[aidefense] Action: {event['event_action']}")
    policy = event.get("policy") or {}
    if policy.get("policy_name"):
        lines.append(f"[aidefense] Policy: {policy['policy_name']}")
    connection = event.get("connection") or {}
    if connection.get("connection_name"):
        lines.append(f"[aidefense] Connection: {connection['connection_name']}")

    guardrails = []
    for match in (event.get("rule_matches") or {}).get("items") or []:
        parts = [
            match.get("guardrail_type"),
            match.get("guardrail_ruleset_type"),
            match.get("guardrail_entity"),
        ]
        label = " / ".join(part for part in parts if part)
        action = match.get("guardrail_action")
        guardrails.append(f"{label} -> {action}" if label and action else label or action or "")
    if guardrails:
        lines.append(f"[aidefense] Guardrails: {'; '.join(item for item in guardrails if item)}")

    return lines


def _run_barrybot(script_name: str, mode: str, prompt: str, extra_env: dict[str, str] | None = None) -> dict:
    """Run a demo script with --mode and --prompt --json; return parsed JSON."""
    script_path = _resolve_run_script(script_name)
    env = _subprocess_env()
    if extra_env:
        env.update(extra_env)
    python_exe = _middleware_python_exe(env) if script_name == "barrybot_middleware.py" else env.get("PYTHON_EXE", "python3")
    result = subprocess.run(
        [
            python_exe,
            script_path.name,
            "--mode",
            mode,
            "--prompt",
            prompt,
            "--json",
        ],
        capture_output=True,
        text=True,
        timeout=60,
        cwd=str(AGENT_DIR),
        env=env,
    )
    if result.returncode != 0 and not result.stdout.strip():
        return {
            "response": None,
            "blocked": True,
            "decision": {"action": "error", "reasons": [_short_error_from_stderr(result.stderr or "")]},
            "logs": _collect_logs(result.stdout, result.stderr),
        }
    # Stdout may have SDK banner line(s) before the JSON (e.g. "[agentsec] LLM: ..."); take last JSON object
    raw = result.stdout.strip()
    try:
        return json.loads(raw)
    except json.JSONDecodeError:
        pass
    # Try from first { to end, then line by line
    start = raw.find("{")
    if start != -1:
        try:
            return json.loads(raw[start:].strip())
        except json.JSONDecodeError:
            pass
    for line in raw.splitlines():
        line = line.strip()
        if line.startswith("{"):
            try:
                return json.loads(line)
            except json.JSONDecodeError:
                continue
    return {
        "response": None,
        "blocked": True,
        "decision": {
            "action": "error",
            "reasons": [
                "Invalid JSON from agent",
                _short_error_from_stderr(result.stderr or "") if result.stderr.strip() else "Subprocess returned non-JSON output",
            ],
        },
        "logs": _collect_logs(result.stdout, result.stderr),
    }


@app.route("/api/health", methods=["GET"])
def health():
    return jsonify({"status": "ok"})


@app.route("/api/source", methods=["GET"])
def source():
    """Return demo source code for the frontend code panel."""
    script_name = request.args.get("script", "barrybot.py")
    try:
        script_path = _resolve_source_script(script_name)
    except (ValueError, FileNotFoundError) as exc:
        return jsonify({"error": str(exc)}), 404
    return script_path.read_text(), 200, {"Content-Type": "text/plain; charset=utf-8"}


@app.route("/api/artifact", methods=["GET"])
def artifact():
    """Return demo artifact content for the frontend detail viewer."""
    artifact_id = request.args.get("id", "")
    try:
        artifact_path = _resolve_artifact(artifact_id)
    except ValueError as exc:
        return jsonify({"error": str(exc)}), 404
    if not artifact_path.exists():
        return jsonify({"error": f"{artifact_path.name} not found"}), 404
    return jsonify({"id": artifact_id, "name": ".data.md", "content": artifact_path.read_text()})


@app.route("/api/run", methods=["POST"])
def run():
    """Run the selected demo script in monitor and enforce modes; return combined results."""
    data = request.get_json() or {}
    prompt = data.get("prompt", "").strip()
    script_name = data.get("script", "barrybot.py")
    if not prompt:
        return jsonify({"error": "prompt is required"}), 400
    try:
        _resolve_run_script(script_name)
    except (ValueError, FileNotFoundError) as exc:
        return jsonify({"error": str(exc)}), 400
    modes = data.get("modes", ["monitor", "enforce"])
    run_id = uuid.uuid4().hex

    results = {}
    with ThreadPoolExecutor(max_workers=2) as executor:
        futures = {
            executor.submit(_run_barrybot, script_name, mode, prompt, _artifact_env(script_name, mode, run_id)): mode
            for mode in modes
        }
        for future in as_completed(futures):
            mode = futures[future]
            try:
                results[mode] = future.result()
            except Exception as e:
                results[mode] = {
                    "response": None,
                    "blocked": True,
                    "decision": {"action": "error", "reasons": [str(e)]},
                    "logs": [],
                }

    for result in results.values():
        decision = result.get("decision") or {}
        result["event_log"] = _fetch_event_log(decision.get("event_id"))

    return jsonify({"prompt": prompt, "script": script_name, "results": results})


if __name__ == "__main__":
    port = int(os.environ.get("PORT", "5001"))
    app.run(debug=True, host="0.0.0.0", port=port)
