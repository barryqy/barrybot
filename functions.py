import json
import logging
import os
import re
import subprocess
import sys
import tempfile
import traceback
from pathlib import Path

def parse_mode(argv: list[str]) -> str:
    for i, arg in enumerate(argv):
        if arg == "--mode" and i + 1 < len(argv) and argv[i + 1] in ("enforce", "monitor", "off"):
            return argv[i + 1]
    return "enforce"


class AgentsecLogCapture(logging.Handler):
    def __init__(self) -> None:
        super().__init__()
        self.lines: list[str] = []

    def emit(self, record: logging.LogRecord) -> None:
        try:
            self.lines.append(self.format(record))
        except Exception:
            pass


def configure_macos_cert_bundle() -> None:
    if sys.platform != "darwin":
        return
    if os.environ.get("SSL_CERT_FILE") or os.environ.get("REQUESTS_CA_BUNDLE"):
        return

    bundle = Path(tempfile.gettempdir()) / "agentsec-macos-system-certs.pem"
    if not bundle.exists() or bundle.stat().st_size == 0:
        result = subprocess.run(
            [
                "security",
                "find-certificate",
                "-a",
                "-p",
                "/Library/Keychains/System.keychain",
                "/System/Library/Keychains/SystemRootCertificates.keychain",
            ],
            capture_output=True,
            text=True,
        )
        if result.returncode != 0 or not result.stdout.strip():
            return
        bundle.write_text(result.stdout)

    os.environ["SSL_CERT_FILE"] = str(bundle)
    os.environ["REQUESTS_CA_BUNDLE"] = str(bundle)


def decision_to_dict(decision) -> dict | None:
    if decision is None:
        return None
    return {
        "action": getattr(decision, "action", "block"),
        "reasons": getattr(decision, "reasons", None),
        "classifications": getattr(decision, "classifications", None),
        "severity": getattr(decision, "severity", None),
        "explanation": getattr(decision, "explanation", None),
        "rules": getattr(decision, "rules", None),
        "event_id": getattr(decision, "event_id", None),
    }


def current_decision() -> tuple[dict | None, str | None]:
    from aidefense.runtime.agentsec._context import get_inspection_context

    ctx = get_inspection_context()
    if ctx.decision is None:
        return None, None
    return decision_to_dict(ctx.decision), ("response" if ctx.done else "request")


def redact(text: str) -> str:
    text = re.sub(r"(?i)\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b", "[EMAIL]", text)
    text = re.sub(r"\b\d{3}-\d{2}-\d{4}\b", "[US_SSN]", text)
    text = re.sub(r"\b\d{3}[-. ]\d{3}[-. ]\d{4}\b", "[PHONE_NUMBER]", text)
    text = re.sub(r"\b\d{10}\b", "[PHONE_NUMBER]", text)
    return text


def captured_logs(log_capture: AgentsecLogCapture | None, redact_values: bool = False) -> list[str]:
    lines = log_capture.lines if log_capture else []
    return [redact(line) for line in lines] if redact_values else lines


def emit_json(payload: dict, exit_code: int = 0) -> None:
    print(json.dumps(payload))
    if exit_code:
        sys.exit(exit_code)


def success_payload(mode: str, prompt: str, reply: str, log_capture: AgentsecLogCapture | None) -> dict:
    decision, decision_stage = current_decision()
    observed_block = mode == "monitor" and bool(decision and decision["action"] == "block")
    return {
        "mode": mode,
        "prompt": prompt,
        "response": reply,
        "blocked": False,
        "observed_block": observed_block,
        "decision": decision,
        "decision_stage": decision_stage,
        "logs": captured_logs(log_capture, redact_values=observed_block),
    }


def security_block_payload(
    mode: str,
    prompt: str,
    decision,
    log_capture: AgentsecLogCapture | None,
) -> dict:
    _, decision_stage = current_decision()
    return {
        "mode": mode,
        "prompt": prompt,
        "response": None,
        "blocked": True,
        "observed_block": False,
        "decision": decision_to_dict(decision),
        "decision_stage": decision_stage,
        "logs": captured_logs(log_capture, redact_values=True),
    }


def unexpected_error_payload(
    mode: str,
    prompt: str,
    exc: Exception,
    log_capture: AgentsecLogCapture | None,
) -> dict:
    return {
        "mode": mode,
        "prompt": prompt,
        "response": None,
        "blocked": True,
        "decision": {
            "action": "error",
            "reasons": [f"{type(exc).__name__}: {exc}"],
            "classifications": None,
            "severity": None,
            "explanation": "Unexpected agent error",
            "rules": None,
            "event_id": None,
        },
        "logs": captured_logs(log_capture) + traceback.format_exc().rstrip().splitlines(),
    }
