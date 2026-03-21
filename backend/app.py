"""
Flask API for agentsec conference demo.
Serves /api/health, /api/run (runs barrybot.py subprocesses), /api/source.
"""

import base64
import importlib.util
import json
import os
import subprocess
import sys
import time
import uuid
from concurrent.futures import ThreadPoolExecutor, as_completed
from functools import lru_cache
from pathlib import Path
from urllib.error import HTTPError, URLError
from urllib.parse import urlencode
from urllib.request import Request, urlopen

from dotenv import dotenv_values, load_dotenv
from flask import Flask, jsonify, request
from flask_cors import CORS

try:
    import yaml
except ImportError:  # pragma: no cover - optional in some local envs
    yaml = None

# Agent directory: parent of backend/ (contains demo scripts, users.db, artifacts)
BACKEND_DIR = Path(__file__).resolve().parent
AGENT_DIR = BACKEND_DIR.parent
AGENTCORE_DIR = AGENT_DIR / "agentcore-barrybot"
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
        "https://dev.aidefense.cisco.com",
        "https://aidefense-dev-portal.vercel.app",
        "http://localhost:4321",
        "http://127.0.0.1:4321",
        "http://localhost:4173",
        "http://127.0.0.1:4173",
    ]


app = Flask(__name__)
CORS(app, origins=corsOrigins())

AGENTCORE_DEMO_KEY = "aws_agentcore"
AGENTCORE_MONITOR_AGENT_NAME = os.environ.get("AGENTCORE_BARRYBOT_MONITOR_AGENT_NAME", "barrybot_agentcore_monitor")
AGENTCORE_ENFORCE_AGENT_NAME = os.environ.get("AGENTCORE_BARRYBOT_ENFORCE_AGENT_NAME", "barrybot_agentcore")
RUN_SCRIPT_FILES = {
    "barrybot.py": AGENT_DIR / "barrybot.py",
    "barrybot_middleware.py": AGENT_DIR / "barrybot_middleware.py",
    "barrybot_mcp.py": AGENT_DIR / "barrybot_mcp.py",
}
SOURCE_FILES = {
    **RUN_SCRIPT_FILES,
    "flight_mcp_server.py": AGENT_DIR / "flight_mcp_server.py",
    AGENTCORE_DEMO_KEY: AGENTCORE_DIR / "agent_factory.py",
    "agentcore_barrybot_app.py": AGENTCORE_DIR / "agentcore_barrybot_app.py",
}
AGENTCORE_INVOKE_SCRIPT = AGENTCORE_DIR / "scripts" / "invoke_bearer.py"
AGENTCORE_CONFIG_FILE = AGENTCORE_DIR / ".bedrock_agentcore.yaml"
ARTIFACT_DIR = AGENT_DIR / ".artifacts"
ARTIFACT_DIR.mkdir(exist_ok=True)
LOCAL_SESSION_CACHE_CANDIDATES = [
    AGENT_DIR.parent / "aidefense" / "session_cache.py",
    AGENT_DIR.parent / "DevNet" / "aidefense" / "aidefense" / "session_cache.py",
]
LOCAL_SESSION_CACHE_FILE_CANDIDATES = [
    AGENT_DIR.parent / "aidefense" / ".aidefense" / ".cache",
    AGENT_DIR.parent / "DevNet" / "aidefense" / "aidefense" / ".aidefense" / ".cache",
]


def _resolve_run_script(script_name: str) -> Path:
    if script_name == AGENTCORE_DEMO_KEY:
        if not AGENTCORE_INVOKE_SCRIPT.exists():
            raise FileNotFoundError(f"{AGENTCORE_INVOKE_SCRIPT.name} not found")
        return AGENTCORE_INVOKE_SCRIPT
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
    for line in reversed(lines):
        line = line.strip()
        if line.startswith(("Error", "error", "Exception", "Traceback")) or "Error:" in line or "Exception:" in line:
            return line[:500]
    for line in reversed(lines):
        if line.strip() and not line.strip().startswith("["):
            return line.strip()[:500]
    return lines[-1].strip()[:500] if lines else "Subprocess failed"


def _collect_logs(*streams: str) -> list[str]:
    """Keep non-empty stdout/stderr payloads so the UI can show raw failure context."""
    return [stream for stream in streams if stream and stream.strip()]


def _filter_noise_lines(lines: list[str]) -> list[str]:
    filtered = []
    for line in lines:
        if "RequestsDependencyWarning" in line:
            continue
        if line.strip() == "warnings.warn(":
            continue
        filtered.append(line)
    return filtered


def _subprocess_env() -> dict[str, str]:
    """Build subprocess env from current process env plus the latest .env values on disk."""
    env = {**os.environ}
    env.update({key: value for key, value in dotenv_values(ENV_PATH).items() if value is not None})
    env.setdefault("PYTHON_EXE", sys.executable)
    return env


def _agentcore_python_exe(env: dict[str, str]) -> str:
    runtime_python = AGENTCORE_DIR / ".venv" / "bin" / "python"
    if runtime_python.exists():
        return str(runtime_python)
    return env.get("PYTHON_EXE", "python3")


def _middleware_python_exe(env: dict[str, str]) -> str:
    runtime_python = MIDDLEWARE_DIR / ".venv" / "bin" / "python"
    if runtime_python.exists():
        try:
            probe = subprocess.run(
                [
                    str(runtime_python),
                    "-c",
                    "import aidefense, aidefense_langchain",
                ],
                capture_output=True,
                text=True,
                timeout=10,
                env=env,
            )
            if probe.returncode == 0:
                return str(runtime_python)
        except Exception:
            pass
    return env.get("PYTHON_EXE", "python3")


@lru_cache(maxsize=8)
def _agentcore_runtime_info(agent_name: str) -> tuple[str | None, str]:
    if not AGENTCORE_CONFIG_FILE.exists() or yaml is None:
        return None, os.environ.get("AWS_REGION", "us-west-2")

    try:
        payload = yaml.safe_load(AGENTCORE_CONFIG_FILE.read_text()) or {}
    except Exception:
        return None, os.environ.get("AWS_REGION", "us-west-2")

    agents = payload.get("agents") or {}
    agent_cfg = agents.get(agent_name) or {}
    bedrock_cfg = agent_cfg.get("bedrock_agentcore") or {}
    aws_cfg = agent_cfg.get("aws") or {}
    agent_id = bedrock_cfg.get("agent_id")
    region = aws_cfg.get("region") or os.environ.get("AWS_REGION", "us-west-2")
    return agent_id, region


def _slice_agentcore_log_lines(lines: list[str], session_id: str | None) -> list[str]:
    if not lines:
        return []
    if not session_id:
        return lines[-30:]

    match_index = -1
    for idx, line in enumerate(lines):
        if session_id in line:
            match_index = idx

    if match_index == -1:
        return lines[-30:]

    start = max(0, match_index - 12)
    return lines[start : match_index + 1]


def _fetch_agentcore_cloudwatch_logs(agent_name: str, started_at_ms: int, session_id: str | None = None) -> list[str]:
    agent_id, region = _agentcore_runtime_info(agent_name)
    if not agent_id:
        return []

    log_group = f"/aws/bedrock-agentcore/runtimes/{agent_id}-DEFAULT"
    start_time = max(started_at_ms - 15_000, 0)
    def extract_lines(events: list[dict]) -> list[str]:
        lines = []
        for event in events:
            message = (event.get("message") or "").strip()
            if not message:
                continue
            for line in message.splitlines():
                line = line.strip()
                if line:
                    lines.append(f"[cloudwatch] {line}")
        return lines

    try:
        import boto3
    except ImportError:
        boto3 = None

    if boto3 is not None:
        client = boto3.client("logs", region_name=region)
        for _ in range(4):
            try:
                payload = client.filter_log_events(
                    logGroupName=log_group,
                    startTime=start_time,
                    limit=80,
                )
            except Exception:
                break

            lines = extract_lines(payload.get("events") or [])
            if lines:
                return _slice_agentcore_log_lines(lines, session_id)
            time.sleep(1)

    for _ in range(4):
        try:
            result = subprocess.run(
                [
                    "aws",
                    "logs",
                    "filter-log-events",
                    "--region",
                    region,
                    "--log-group-name",
                    log_group,
                    "--start-time",
                    str(start_time),
                    "--limit",
                    "80",
                    "--output",
                    "json",
                ],
                capture_output=True,
                text=True,
                timeout=15,
            )
        except Exception:
            return []

        if result.returncode != 0:
            time.sleep(1)
            continue

        try:
            payload = json.loads(result.stdout or "{}")
        except json.JSONDecodeError:
            time.sleep(1)
            continue

        lines = extract_lines(payload.get("events") or [])
        if lines:
            return _slice_agentcore_log_lines(lines, session_id)
        time.sleep(1)

    return []


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

    for cache_file in LOCAL_SESSION_CACHE_FILE_CANDIDATES:
        if not cache_file.exists():
            continue
        try:
            token = None
            for line in cache_file.read_text().splitlines():
                line = line.strip()
                if line.startswith("session_token="):
                    token = line.split("=", 1)[1].strip()
                    break
            if not token:
                continue
            data = base64.b64decode(token)
            env_key = os.environ.get("DEVENV_USER", "default-key-fallback")
            repeated_key = (env_key * (len(data) // len(env_key) + 1))[: len(data)]
            plaintext = bytes(a ^ b for a, b in zip(data, repeated_key.encode())).decode("utf-8")
            parts = plaintext.split(":")
            if len(parts) > 4 and parts[4] and parts[4] != "none":
                return parts[4]
        except Exception:
            pass

    for session_cache in LOCAL_SESSION_CACHE_CANDIDATES:
        if not session_cache.exists():
            continue
        try:
            spec = importlib.util.spec_from_file_location("agentsec_session_cache", session_cache)
            if not spec or not spec.loader:
                continue
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
    raw = result.stdout.strip()
    try:
        return json.loads(raw)
    except json.JSONDecodeError:
        pass
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


def _parse_agentcore_output(result: subprocess.CompletedProcess[str], mode: str) -> dict:
    stdout_lines = [line.strip() for line in (result.stdout or "").splitlines() if line.strip()]
    stderr_lines = _filter_noise_lines([line.strip() for line in (result.stderr or "").splitlines() if line.strip()])

    visible_lines = []
    aux_logs = []
    for line in stdout_lines:
        if line.startswith("[agentsec]"):
            aux_logs.append(line)
            continue
        visible_lines.append(line)

    message = "\n".join(visible_lines).strip()
    logs = _collect_logs("\n".join(aux_logs), "\n".join(stderr_lines))

    if message.startswith("Blocked by AI Defense"):
        reasons = []
        reason_text = message.split(":", 1)[1].strip() if ":" in message else ""
        if reason_text:
            reasons.append(reason_text)
        return {
            "response": None,
            "blocked": True,
            "decision": {"action": "block", "reasons": reasons},
            "logs": logs,
            "agentcore": {
                "invoke_path": "runtime_direct",
                "runtime_mode": mode,
                "runtime": "aws_agentcore",
            },
        }

    if result.returncode == 0 and message:
        return {
            "response": message,
            "blocked": False,
            "decision": {"action": "allow"},
            "logs": logs,
            "agentcore": {
                "invoke_path": "runtime_direct",
                "runtime_mode": mode,
                "runtime": "aws_agentcore",
            },
        }

    short_error = _short_error_from_stderr(result.stderr or "")
    if not short_error and visible_lines:
        short_error = visible_lines[-1]
    return {
        "response": None,
        "blocked": True,
        "decision": {"action": "error", "reasons": [short_error or "AgentCore invocation failed"]},
        "logs": _collect_logs(result.stdout, result.stderr),
        "agentcore": {
            "invoke_path": "runtime_direct",
            "runtime_mode": mode,
            "runtime": "aws_agentcore",
        },
    }


def _run_agentcore(mode: str, prompt: str) -> dict:
    if not AGENTCORE_INVOKE_SCRIPT.exists():
        raise FileNotFoundError(f"AgentCore invoke script not found for mode: {mode}")
    runtime_name = AGENTCORE_MONITOR_AGENT_NAME if mode == "monitor" else AGENTCORE_ENFORCE_AGENT_NAME

    env = _subprocess_env()
    session_id = f"session-{uuid.uuid4().hex}"
    env["AGENTCORE_BARRYBOT_AGENT_NAME"] = runtime_name
    env["AGENTCORE_SESSION_ID"] = session_id
    started_at_ms = int(time.time() * 1000)
    result = subprocess.run(
        [
            _agentcore_python_exe(env),
            str(AGENTCORE_INVOKE_SCRIPT),
            prompt,
        ],
        capture_output=True,
        text=True,
        timeout=90,
        cwd=str(AGENTCORE_DIR),
        env=env,
    )
    parsed = _parse_agentcore_output(result, mode)
    parsed["agentcore"]["agent_name"] = runtime_name
    parsed["agentcore"]["session_id"] = session_id
    cloudwatch_logs = _fetch_agentcore_cloudwatch_logs(runtime_name, started_at_ms, session_id)
    if cloudwatch_logs:
        parsed["logs"] = [*cloudwatch_logs, *(parsed.get("logs") or [])]
    return parsed


def _run_demo(script_name: str, mode: str, prompt: str, extra_env: dict[str, str] | None = None) -> dict:
    if script_name == AGENTCORE_DEMO_KEY:
        return _run_agentcore(mode, prompt)
    return _run_barrybot(script_name, mode, prompt, extra_env)


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
            executor.submit(_run_demo, script_name, mode, prompt, _artifact_env(script_name, mode, run_id)): mode
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
