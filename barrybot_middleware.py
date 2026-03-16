#!/usr/bin/env python3
"""
BarryBot using AIDefenseAgentsecMiddleware.

Usage: python3 barrybot_middleware.py --mode monitor|enforce --prompt "..." --json
"""

import argparse, logging, os, sqlite3, sys
from pathlib import Path

from langchain.agents.middleware import hook_config
from functions import (
    AgentsecLogCapture,
    configure_macos_cert_bundle,
    emit_json,
    parse_mode,
    redact,
    unexpected_error_payload,
)

MODE = parse_mode(sys.argv[1:])
configure_macos_cert_bundle()

MIDDLEWARE_ROOTS = [
    Path(os.environ.get("LANGCHAIN_MIDDLEWARE_DIR", "")).expanduser(),
    Path.home() / "code" / "ai-defense-langchain-middleware-personal",
]

for root in MIDDLEWARE_ROOTS:
    src_dir = root / "src"
    if src_dir.exists():
        sys.path.insert(0, str(src_dir))
        break

from langchain.agents import create_agent
from langchain_core.messages import AIMessage
from langchain_core.tools import tool
from langchain_openai import ChatOpenAI
from aidefense_langchain import AIDefenseAgentsecMiddleware

# ---------------------------------------------------------------------------
# Database
# ---------------------------------------------------------------------------

DB_PATH = "users.db"
SEED_USERS = [
    ("Barry", "Yuan", "bayuan@cisco.com", "123-12-1212", "6045555555"),
    ("Alice", "Smith", "alice.smith@example.com", "123-45-6789", "5551234567"),
    ("Bob", "Johnson", "bob.johnson@example.com", "987-65-4321", "5559876543"),
]
SYSTEM_PROMPT = (
    "You are BarryBot, a helpful AI assistant with access to a user database. "
    "When the user asks about people, users, or their information, use the "
    "query_database tool to look up the data. Write your own SQL SELECT queries "
    "against the 'users' table (columns: id, first_name, last_name, email, ssn, phone). "
    "Always base your answers on actual query results — never guess or fabricate data. "
    "Be concise and friendly. Optimize output for small narrow screens."
)


def init_database() -> None:
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY,
            first_name TEXT,
            last_name TEXT,
            email TEXT,
            ssn TEXT,
            phone TEXT
        )
        """
    )
    cur.execute("SELECT COUNT(*) FROM users")
    if cur.fetchone()[0] == 0:
        cur.executemany(
            "INSERT INTO users (first_name, last_name, email, ssn, phone) VALUES (?, ?, ?, ?, ?)",
            SEED_USERS,
        )
    conn.commit()
    conn.close()


# ---------------------------------------------------------------------------
# LangChain Tool
# ---------------------------------------------------------------------------


@tool
def query_database(sql: str) -> str:
    """Run SQL against users(id, first_name, last_name, email, ssn, phone)."""
    sql = sql.strip().rstrip(";")
    if not sql:
        return "Error: SQL is required."

    if not sql.upper().startswith("SELECT"):
        return "Error: Only SELECT queries are allowed."

    try:
        conn = sqlite3.connect(DB_PATH)
        conn.row_factory = sqlite3.Row
        cur = conn.cursor()
        cur.execute(sql)
        rows = cur.fetchall()
        conn.close()
    except sqlite3.Error as exc:
        return f"SQL error: {exc}"

    if not rows:
        return "No results found."

    columns = rows[0].keys()
    lines = [" | ".join(columns), "-" * 40]
    for row in rows:
        lines.append(" | ".join(str(row[column]) for column in columns))
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Middleware Agent
# ---------------------------------------------------------------------------


class MistralChatOpenAI(ChatOpenAI):
    # langchain-openai rewrites max_tokens into max_completion_tokens, which Mistral rejects.
    def _get_request_payload(self, input_, *, stop=None, **kwargs):
        payload = super()._get_request_payload(input_, stop=stop, **kwargs)
        if "max_completion_tokens" in payload:
            payload["max_tokens"] = payload.pop("max_completion_tokens")
        return payload


def middleware_env(mode: str) -> dict[str, str]:
    data = dict(os.environ)
    data["AIDEFENSE_MODE"] = mode
    data.setdefault("AIDEFENSE_API_KEY", data.get("AI_DEFENSE_API_KEY", ""))
    data.setdefault(
        "AIDEFENSE_ENDPOINT",
        data.get("AI_DEFENSE_ENDPOINT", "https://us.api.inspect.aidefense.security.cisco.com/api"),
    )
    data.setdefault("AIDEFENSE_FAIL_OPEN", "true")
    data.setdefault("AIDEFENSE_TIMEOUT_MS", "30000")
    data.setdefault("AIDEFENSE_RETRY_TOTAL", "1")
    data.setdefault("AIDEFENSE_RETRY_BACKOFF", "0")
    return data


class MiddlewareTrace:
    def __init__(self) -> None:
        self.last_phase = None
        self.last_decision = None
        self.observed = []

    def _remember(self, phase, decision):
        if not decision:
            return
        self.last_phase = phase
        self.last_decision = decision
        self.observed.append((phase, decision))

    def remember_llm(self, decision, direction):
        phase = "input" if direction == "input" else "output"
        self._remember(phase, decision)


def _normalized_message_content(msg) -> str:
    content = getattr(msg, "content", "")
    if isinstance(content, str) and content.strip():
        return content
    if isinstance(content, list):
        parts = []
        for item in content:
            if isinstance(item, dict) and item.get("type") == "text":
                value = str(item.get("text", "")).strip()
                if value:
                    parts.append(value)
            elif str(item).strip():
                parts.append(str(item).strip())
        if parts:
            return "\n".join(parts)
    if getattr(msg, "tool_calls", None):
        return "[tool call requested]"
    if getattr(msg, "tool_call_id", None):
        return "[tool result]"
    return "[empty message]"


class DemoAIDefenseMiddleware(AIDefenseAgentsecMiddleware):
    def __init__(self, trace, *args, **kwargs):
        self.trace = trace
        super().__init__(*args, **kwargs)

    def _normalized_messages(self, messages) -> list[dict]:
        result = []
        for msg in messages:
            role = {
                "human": "user",
                "ai": "assistant",
                "system": "system",
            }.get(getattr(msg, "type", ""), "user")
            result.append({"role": role, "content": _normalized_message_content(msg)})
        return result

    @hook_config(can_jump_to=["end"])
    def before_model(self, state, runtime):
        if self.mode == "off":
            return None
        decision = self.inspector.inspect_conversation(self._normalized_messages(state["messages"]), self._metadata)
        return self._process_decision(decision, "input")

    @hook_config(can_jump_to=["end"])
    def after_model(self, state, runtime):
        if self.mode == "off":
            return None
        decision = self.inspector.inspect_conversation(self._normalized_messages(state["messages"]), self._metadata)
        return self._process_decision(decision, "output")

    def _process_decision(self, decision, direction):
        self.trace.remember_llm(decision, direction)
        return super()._process_decision(decision, direction)


def build_agent():
    api_key = os.environ.get("MISTRAL_API_KEY")
    if not api_key:
        raise ValueError("MISTRAL_API_KEY not set.")

    trace = MiddlewareTrace()
    mw_env = middleware_env(MODE)
    middleware = [
        DemoAIDefenseMiddleware(
            trace,
            mode=mw_env.get("AIDEFENSE_MODE", MODE),
            api_key=mw_env.get("AIDEFENSE_API_KEY"),
            endpoint=mw_env.get("AIDEFENSE_ENDPOINT"),
            fail_open=mw_env.get("AIDEFENSE_FAIL_OPEN", "true").lower() in ("1", "true", "yes", "on"),
            timeout_ms=int(mw_env.get("AIDEFENSE_TIMEOUT_MS", "30000")),
            retry_total=int(mw_env.get("AIDEFENSE_RETRY_TOTAL", "1")),
            retry_backoff=float(mw_env.get("AIDEFENSE_RETRY_BACKOFF", "0")),
        ),
    ]

    agent = create_agent(
        MistralChatOpenAI(
            model="mistral-small-latest",
            api_key=api_key,
            base_url="https://api.mistral.ai/v1",
            temperature=0.7,
            max_tokens=512,
        ),
        tools=[query_database],
        middleware=middleware,
        system_prompt=SYSTEM_PROMPT,
    )
    return agent, trace


def flatten_text(content) -> str:
    if isinstance(content, str):
        return content
    if isinstance(content, list):
        parts = []
        for item in content:
            if isinstance(item, dict) and item.get("type") == "text":
                parts.append(str(item.get("text", "")))
            else:
                parts.append(str(item))
        return "\n".join(part for part in parts if part).strip()
    return str(content or "")


def final_reply(result: dict) -> str:
    for message in reversed(result.get("messages", [])):
        if isinstance(message, AIMessage):
            reply = flatten_text(getattr(message, "content", ""))
            if reply:
                return reply
    return ""


def middleware_decision_to_dict(decision) -> dict | None:
    if decision is None:
        return None

    rules = []
    for rule in getattr(decision, "rules", None) or []:
        if isinstance(rule, dict):
            rules.append(rule)
            continue
        rules.append(
            {
                "rule_name": getattr(rule, "rule_name", None),
                "classification": getattr(rule, "classification", None),
            }
        )

    return {
        "action": getattr(decision, "action", "block"),
        "reasons": getattr(decision, "reasons", None),
        "classifications": getattr(decision, "classifications", None),
        "severity": getattr(decision, "severity", None),
        "explanation": getattr(decision, "explanation", None),
        "rules": rules,
        "event_id": getattr(decision, "event_id", None),
    }


def middleware_stage(phase: str | None) -> str | None:
    if not phase:
        return None
    if phase == "input":
        return "request"
    if phase == "output":
        return "response"
    return phase


def middleware_logs(log_capture: AgentsecLogCapture | None, *, redact_values: bool = False) -> list[str]:
    lines = log_capture.lines if log_capture else []
    return [redact(line) for line in lines] if redact_values else lines


def middleware_success_payload(mode: str, prompt: str, reply: str, trace, log_capture: AgentsecLogCapture | None) -> dict:
    decision = middleware_decision_to_dict(trace.last_decision)
    observed_block = mode == "monitor" and bool(decision and decision["action"] == "block")
    return {
        "mode": mode,
        "prompt": prompt,
        "response": reply,
        "blocked": False,
        "observed_block": observed_block,
        "decision": decision or {"action": "allow"},
        "decision_stage": middleware_stage(trace.last_phase),
        "logs": middleware_logs(log_capture, redact_values=observed_block),
    }


def middleware_block_payload(mode: str, prompt: str, trace, decision, log_capture: AgentsecLogCapture | None) -> dict:
    return {
        "mode": mode,
        "prompt": prompt,
        "response": None,
        "blocked": True,
        "decision": middleware_decision_to_dict(decision),
        "decision_stage": middleware_stage(trace.last_phase),
        "logs": middleware_logs(log_capture, redact_values=True),
    }


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------


def main() -> None:
    parser = argparse.ArgumentParser(description="BarryBot middleware demo agent")
    parser.add_argument("--mode", choices=["enforce", "monitor", "off"], default="enforce")
    parser.add_argument("--prompt", required=True)
    parser.add_argument("--json", action="store_true", required=True)
    args = parser.parse_args()

    log_capture = None
    if os.environ.get("AGENTSEC_CAPTURE_LOGS"):
        log_capture = AgentsecLogCapture()
        log_capture.setFormatter(logging.Formatter("%(message)s"))
        for logger_name in ("aidefense.langchain", "aidefense.langchain.agentsec", "aidefense.langchain.tools.agentsec"):
            logger = logging.getLogger(logger_name)
            logger.setLevel(logging.DEBUG)
            logger.addHandler(log_capture)

    init_database()
    agent, trace = build_agent()

    try:
        result = agent.invoke(
            {
                "messages": [
                    {
                        "role": "user",
                        "content": args.prompt,
                    }
                ]
            }
        )
        decision = trace.last_decision
        blocked = MODE == "enforce" and bool(decision and decision.action == "block")
        if blocked:
            emit_json(middleware_block_payload(MODE, args.prompt, trace, decision, log_capture), exit_code=1)
            return

        emit_json(middleware_success_payload(MODE, args.prompt, final_reply(result), trace, log_capture))
    except Exception as exc:
        emit_json(unexpected_error_payload(MODE, args.prompt, exc, log_capture), exit_code=1)


if __name__ == "__main__":
    main()
