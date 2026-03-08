#!/usr/bin/env python3
"""
BarryBot - AI Agent secured by Cisco AI Defense agentsec.

Usage: python3 barrybot.py --mode monitor|enforce --prompt "..." --json
"""

import argparse, logging, os, sqlite3, sys

from functions import (
    AgentsecLogCapture,
    configure_macos_cert_bundle,
    emit_json,
    parse_mode,
    security_block_payload,
    success_payload,
    unexpected_error_payload,
)

MODE = parse_mode(sys.argv[1:])
configure_macos_cert_bundle()

# Only 2 lines of code to add enterprise-grade security to a LangChain agent:
from aidefense.runtime import agentsec

agentsec.protect(
    api_mode={
        "llm": {
            "mode": MODE,
            "endpoint": os.environ.get("AI_DEFENSE_ENDPOINT", "https://us.api.inspect.aidefense.security.cisco.com/api"),
            "api_key": os.environ.get("AI_DEFENSE_API_KEY", ""),
        },
    },
    auto_dotenv=False,
)

from aidefense.runtime.agentsec._context import clear_inspection_context
from aidefense.runtime.agentsec.exceptions import SecurityPolicyError
from langchain_core.messages import HumanMessage, SystemMessage, ToolMessage
from langchain_core.tools import tool
from langchain_openai import ChatOpenAI

# ---------------------------------------------------------------------------
# Database
# ---------------------------------------------------------------------------

DB_PATH = "users.db"
MAX_ITERATIONS = 5
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
# Agent loop
# ---------------------------------------------------------------------------


def build_agent():
    api_key = os.environ.get("MISTRAL_API_KEY")
    if not api_key:
        raise ValueError("MISTRAL_API_KEY not set.")

    llm = ChatOpenAI(
        model="mistral-small-latest",
        api_key=api_key,
        base_url="https://api.mistral.ai/v1",
        temperature=0.7,
        max_tokens=512,
    )
    tools = [query_database]
    return llm.bind_tools(tools), {tool_.name: tool_ for tool_ in tools}


def run_agent_loop(llm_with_tools, tools_dict: dict, messages: list) -> str:
    for _ in range(MAX_ITERATIONS):
        response = llm_with_tools.invoke(messages)
        messages.append(response)

        if not response.tool_calls:
            return response.content or ""

        for tool_call in response.tool_calls:
            name = tool_call["name"]
            args = tool_call["args"]
            tool_call_id = tool_call["id"]
            if name in tools_dict:
                try:
                    result = tools_dict[name].invoke(args)
                except SecurityPolicyError:
                    raise
                except Exception as exc:
                    result = f"Tool error: {exc}"
            else:
                result = f"Unknown tool: {name}"
            messages.append(ToolMessage(content=str(result), tool_call_id=tool_call_id))

    return "Max iterations reached."


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------


def main() -> None:
    parser = argparse.ArgumentParser(description="BarryBot demo agent")
    parser.add_argument("--mode", choices=["enforce", "monitor", "off"], default="enforce")
    parser.add_argument("--prompt", required=True)
    parser.add_argument("--json", action="store_true", required=True)
    args = parser.parse_args()

    log_capture = None
    if os.environ.get("AGENTSEC_CAPTURE_LOGS"):
        log_capture = AgentsecLogCapture()
        log_capture.setFormatter(logging.Formatter("%(message)s"))
        logger = logging.getLogger("aidefense.runtime.agentsec")
        logger.setLevel(logging.DEBUG)
        logger.addHandler(log_capture)

    clear_inspection_context()
    init_database()
    llm_with_tools, tools_dict = build_agent()
    messages = [SystemMessage(content=SYSTEM_PROMPT), HumanMessage(content=args.prompt)]

    try:
        reply = run_agent_loop(llm_with_tools, tools_dict, messages)
        emit_json(success_payload(MODE, args.prompt, reply, log_capture))
    except SecurityPolicyError as exc:
        emit_json(security_block_payload(MODE, args.prompt, exc.decision, log_capture), exit_code=1)
    except Exception as exc:
        emit_json(unexpected_error_payload(MODE, args.prompt, exc, log_capture), exit_code=1)


if __name__ == "__main__":
    main()
