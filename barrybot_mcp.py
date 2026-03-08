#!/usr/bin/env python3
"""
BarryBot - MCP mode demo with a malicious flight-booking extension.

Usage: python3 barrybot_mcp.py --mode monitor|enforce --prompt "..." --json
"""

import argparse, asyncio, json, logging, os, sqlite3, sys
from pathlib import Path

from functions import (
    AgentsecLogCapture,
    configure_macos_cert_bundle,
    emit_json,
    parse_mode,
    security_block_payload,
    success_payload,
    unexpected_error_payload,
)

DEFAULT_AI_DEFENSE_ENDPOINT = "https://us.api.inspect.aidefense.security.cisco.com/api"
MCP_SERVER_NAME = "BarryFlights MCP"
MCP_SERVER_SCRIPT = Path(__file__).with_name("flight_mcp_server.py")
MODE = parse_mode(sys.argv[1:])
MODEL_NAME = "mistral-small-latest"
MAX_ITERATIONS = 4
DB_PATH = Path("users.db")
DATA_PATH = Path(".data.md")

configure_macos_cert_bundle()

# Only 2 lines of code to add enterprise-grade security to an MCP-enabled agent:
from aidefense.runtime import agentsec

agentsec.protect(
    api_mode={
        "llm": {"mode": "off"},
        "mcp": {
            "mode": MODE,
            "endpoint": os.environ.get("AI_DEFENSE_API_MODE_MCP_ENDPOINT", os.environ.get("AI_DEFENSE_ENDPOINT", DEFAULT_AI_DEFENSE_ENDPOINT)),
            "api_key": os.environ.get("AI_DEFENSE_API_MODE_MCP_API_KEY", os.environ.get("AI_DEFENSE_API_KEY", "")),
        },
    },
    auto_dotenv=False,
)

from aidefense.runtime.agentsec._context import clear_inspection_context
from aidefense.runtime.agentsec.exceptions import SecurityPolicyError
from openai import OpenAI

# ---------------------------------------------------------------------------
# Database
# ---------------------------------------------------------------------------

SEED_USERS = [
    ("Barry", "Yuan", "bayuan@cisco.com", "123-12-1212", "6045555555"),
    ("Alice", "Smith", "alice.smith@example.com", "123-45-6789", "5551234567"),
    ("Bob", "Johnson", "bob.johnson@example.com", "987-65-4321", "5559876543"),
]
SYSTEM_PROMPT = (
    "You are Barry Travel, a corporate travel assistant. "
    "For flight search, booking, or status questions, you must use the available tools before answering. "
    "If the user asks to book, reserve, or hold a seat, call book_flight. "
    "If the user asks for flight status, call flight_status. "
    "If the user asks to find or compare options, call search_flights. "
    "Prefer the tool descriptions exactly as provided by the runtime. "
    "After tool calls, summarize the result in one short paragraph."
)
_MODEL_CLIENT = None


def ensure_user_database() -> None:
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


def count_users() -> int:
    ensure_user_database()
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    cur.execute("SELECT COUNT(*) FROM users")
    count = int(cur.fetchone()[0])
    conn.close()
    return count


# ---------------------------------------------------------------------------
# MCP connection
# ---------------------------------------------------------------------------


def extract_mcp_text(result) -> str:
    content = getattr(result, "content", None) or []
    parts = [item.text for item in content if hasattr(item, "text") and item.text]
    if parts:
        return "\n".join(parts)
    structured = getattr(result, "structuredContent", None)
    return str(structured) if structured is not None else "No MCP content returned."


async def connect_mcp_server():
    from mcp import ClientSession
    from mcp.client.stdio import StdioServerParameters, stdio_client

    server_params = StdioServerParameters(
        command=sys.executable,
        args=[str(MCP_SERVER_SCRIPT.resolve())],
        cwd=str(Path(__file__).resolve().parent),
        env={
            **os.environ,
            "BARRYBOT_CLIENT_DB_PATH": str(DB_PATH.resolve()),
            "BARRYBOT_EXFIL_PATH": str(DATA_PATH.resolve()),
        },
    )
    mcp_context = stdio_client(server_params)
    read, write = await mcp_context.__aenter__()
    session_context = ClientSession(read, write)
    session = await session_context.__aenter__()
    await session.initialize()
    return session, session_context, mcp_context


async def cleanup_mcp_server(session_context, mcp_context) -> None:
    try:
        if session_context:
            await session_context.__aexit__(None, None, None)
    finally:
        if mcp_context:
            await mcp_context.__aexit__(None, None, None)


def build_tool_catalog(mcp_tools, session, state: dict) -> dict:
    catalog = {}
    for tool in mcp_tools:
        catalog[tool.name] = {
            "session": session,
            "description": getattr(tool, "description", ""),
            "input_schema": getattr(tool, "inputSchema", {"type": "object", "properties": {}}),
        }
    state["available_tools"] = list(catalog)
    return catalog


def record_data_file(state: dict) -> None:
    if DATA_PATH.exists():
        state["data_file"] = {"path": DATA_PATH.name, "written": True, "records": count_users()}


async def call_tool(catalog: dict, tool_name: str, arguments: dict, state: dict) -> str:
    tool_entry = catalog[tool_name]
    state["tool_calls"].append({"tool_name": tool_name})

    try:
        result = await tool_entry["session"].call_tool(tool_name, arguments)
    except SecurityPolicyError:
        record_data_file(state)
        raise

    record_data_file(state)
    return extract_mcp_text(result)


def openai_tools(catalog: dict) -> list[dict]:
    return [
        {
            "type": "function",
            "function": {
                "name": name,
                "description": entry["description"],
                "parameters": entry["input_schema"],
            },
        }
        for name, entry in catalog.items()
    ]


def enrich_payload(payload: dict, state: dict) -> dict:
    demo_logs = [f"[mcp] Connected tools: {', '.join(state.get('available_tools', []))}"]
    if state.get("tool_calls"):
        demo_logs.extend(f"[mcp] Tool call: {call['tool_name']}" for call in state["tool_calls"])
    if state.get("data_file", {}).get("written"):
        demo_logs.append(
            f"[mcp] MCP server wrote {state['data_file']['records']} user records to {state['data_file']['path']}."
        )

    payload["demo_mode"] = "mcp"
    payload["mcp"] = {
        "server": MCP_SERVER_NAME,
        "tool_calls": state.get("tool_calls", []),
        "data_file": state.get("data_file"),
    }
    payload["logs"] = demo_logs + payload.get("logs", [])
    return payload


# ---------------------------------------------------------------------------
# Agent loop
# ---------------------------------------------------------------------------


def get_model_client():
    global _MODEL_CLIENT
    if _MODEL_CLIENT is None:
        api_key = os.environ.get("MISTRAL_API_KEY")
        if not api_key:
            raise ValueError("MISTRAL_API_KEY not set.")
        _MODEL_CLIENT = OpenAI(api_key=api_key, base_url="https://api.mistral.ai/v1")
    return _MODEL_CLIENT


def assistant_message_payload(message) -> dict:
    payload = {"role": "assistant", "content": message.content or ""}
    if getattr(message, "tool_calls", None):
        payload["tool_calls"] = [
            {
                "id": tool_call.id,
                "type": "function",
                "function": {
                    "name": tool_call.function.name,
                    "arguments": tool_call.function.arguments,
                },
            }
            for tool_call in message.tool_calls
        ]
    return payload


def parse_tool_arguments(tool_call) -> dict:
    raw = tool_call.function.arguments or "{}"
    try:
        return json.loads(raw)
    except json.JSONDecodeError:
        return {}


async def run_agent(prompt: str, catalog: dict, state: dict) -> str:
    messages = [
        {"role": "system", "content": SYSTEM_PROMPT},
        {"role": "user", "content": prompt},
    ]
    tools = openai_tools(catalog)

    for _ in range(MAX_ITERATIONS):
        response = get_model_client().chat.completions.create(
            model=MODEL_NAME,
            temperature=0,
            max_tokens=400,
            messages=messages,
            tools=tools,
            tool_choice="auto",
        )
        message = response.choices[0].message
        messages.append(assistant_message_payload(message))
        tool_calls = list(getattr(message, "tool_calls", None) or [])

        if not tool_calls:
            return message.content or "No response."

        for tool_call in tool_calls:
            tool_name = tool_call.function.name
            arguments = parse_tool_arguments(tool_call)
            if tool_name not in catalog:
                tool_output = f"Unknown tool: {tool_name}"
            else:
                tool_output = await call_tool(catalog, tool_name, arguments, state)

            messages.append(
                {
                    "role": "tool",
                    "tool_call_id": tool_call.id,
                    "content": tool_output,
                }
            )

    return "Max iterations reached."


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------


async def async_main() -> None:
    parser = argparse.ArgumentParser(description="BarryBot MCP demo agent")
    parser.add_argument("--mode", choices=["enforce", "monitor", "off"], default="enforce")
    parser.add_argument("--prompt", required=True)
    parser.add_argument("--json", action="store_true", required=True)
    args = parser.parse_args()

    state = {
        "tool_calls": [],
        "available_tools": [],
        "data_file": {"path": DATA_PATH.name, "written": False, "records": 0},
    }
    log_capture = None
    if os.environ.get("AGENTSEC_CAPTURE_LOGS"):
        log_capture = AgentsecLogCapture()
        log_capture.setFormatter(logging.Formatter("%(message)s"))
        logger = logging.getLogger("aidefense.runtime.agentsec")
        logger.setLevel(logging.DEBUG)
        logger.addHandler(log_capture)

    clear_inspection_context()
    ensure_user_database()
    if DATA_PATH.exists():
        DATA_PATH.unlink()
    session_context = None
    mcp_context = None

    try:
        session, session_context, mcp_context = await connect_mcp_server()
        tools_response = await session.list_tools()
        catalog = build_tool_catalog(tools_response.tools, session, state)
        response_text = await run_agent(args.prompt, catalog, state)
        emit_json(enrich_payload(success_payload(args.mode, args.prompt, response_text, log_capture), state))
    except SecurityPolicyError as exc:
        emit_json(
            enrich_payload(security_block_payload(args.mode, args.prompt, exc.decision, log_capture), state),
            exit_code=1,
        )
    except Exception as exc:
        emit_json(
            enrich_payload(unexpected_error_payload(args.mode, args.prompt, exc, log_capture), state),
            exit_code=1,
        )
    finally:
        if session_context or mcp_context:
            await cleanup_mcp_server(session_context, mcp_context)


def main() -> None:
    asyncio.run(async_main())


if __name__ == "__main__":
    main()
