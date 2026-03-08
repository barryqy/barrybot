"""
Flask API for agentsec conference demo.
Serves /api/health, /api/run (runs barrybot.py subprocesses), /api/source.
"""

import os
import json
import subprocess
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor, as_completed

from dotenv import dotenv_values, load_dotenv
from flask import Flask, request, jsonify
from flask_cors import CORS

# Agent directory: parent of backend/ (contains demo scripts, users.db, artifacts)
BACKEND_DIR = Path(__file__).resolve().parent
AGENT_DIR = BACKEND_DIR.parent
ENV_PATH = AGENT_DIR / ".env"
# Load .env from agent dir so local debugging still works in this Flask process.
load_dotenv(ENV_PATH, override=True)

app = Flask(__name__)
CORS(app, origins=["https://barrysecure.com", "http://localhost:4321", "http://127.0.0.1:4321"])

# PYTHONPATH: use cloned ai-defense-python-sdk (commit 12acfba) when present, else AGENT_DIR
SDK_ROOT = AGENT_DIR / ".reference" / "ai-defense-python-sdk-agentsec-changes"
REPO_ROOT = SDK_ROOT if SDK_ROOT.exists() else AGENT_DIR
RUN_SCRIPT_FILES = {
    "barrybot.py": AGENT_DIR / "barrybot.py",
    "barrybot_mcp.py": AGENT_DIR / "barrybot_mcp.py",
}
SOURCE_FILES = {
    **RUN_SCRIPT_FILES,
    "flight_mcp_server.py": AGENT_DIR / "flight_mcp_server.py",
}
ARTIFACT_FILES = {
    ".data.md": AGENT_DIR / ".data.md",
}


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


def _resolve_artifact(name: str) -> Path:
    artifact_path = ARTIFACT_FILES.get(name)
    if not artifact_path:
        raise ValueError(f"Unsupported artifact: {name}")
    return artifact_path


def _clear_artifacts(*names: str) -> None:
    for name in names:
        artifact_path = ARTIFACT_FILES.get(name)
        if artifact_path and artifact_path.exists():
            artifact_path.unlink()


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


def _run_barrybot(script_name: str, mode: str, prompt: str) -> dict:
    """Run a demo script with --mode and --prompt --json; return parsed JSON."""
    script_path = _resolve_run_script(script_name)
    env = _subprocess_env()
    result = subprocess.run(
        [
            env.get("PYTHON_EXE", "python3"),
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
    name = request.args.get("name", "")
    try:
        artifact_path = _resolve_artifact(name)
    except ValueError as exc:
        return jsonify({"error": str(exc)}), 404
    if not artifact_path.exists():
        return jsonify({"error": f"{artifact_path.name} not found"}), 404
    return jsonify({"name": artifact_path.name, "content": artifact_path.read_text()})


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
    if script_name == "barrybot_mcp.py":
        _clear_artifacts(".data.md")
    modes = data.get("modes", ["monitor", "enforce"])

    results = {}
    with ThreadPoolExecutor(max_workers=2) as executor:
        futures = {
            executor.submit(_run_barrybot, script_name, mode, prompt): mode for mode in modes
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

    return jsonify({"prompt": prompt, "script": script_name, "results": results})


if __name__ == "__main__":
    port = int(os.environ.get("PORT", "5001"))
    app.run(debug=True, host="0.0.0.0", port=port)
