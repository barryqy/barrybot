"""BarryBot as an AWS Bedrock AgentCore app.

Deploy with: ./scripts/deploy.sh
Invoke with: ./scripts/invoke.sh "List all user emails" or use AWS_BEARER_TOKEN_BEDROCK in invoke_bearer.py
"""

import os
import re
import sys
import uuid

# Add parent so agentcore-barrybot is importable
_ROOT = os.path.dirname(os.path.abspath(__file__))
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)

from bedrock_agentcore import BedrockAgentCoreApp

from agent_factory import get_agent
from aidefense.runtime import agentsec
from aidefense.runtime.agentsec._context import clear_inspection_context
from aidefense.runtime.agentsec.exceptions import SecurityPolicyError
from tools import query_database

app = BedrockAgentCoreApp()
EMAIL_RE = re.compile(r"[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}", re.IGNORECASE)


def _ai_defense_block_response(decision):
    """Build response when AI Defense blocks (enforce mode)."""
    reasons = getattr(decision, "reasons", None) or []
    msg = "Request or response blocked by AI Defense (security policy)."
    if reasons:
        msg = "Blocked by AI Defense: " + "; ".join(reasons)
    return {
        "result": msg,
        "blocked": True,
        "blocked_by": "AI Defense",
        "block_reasons": list(reasons),
    }


def _looks_like_email_list_prompt(prompt: str) -> bool:
    prompt_text = (prompt or "").lower()
    if "email" not in prompt_text:
        return False
    return "list" in prompt_text or "all" in prompt_text


def _email_list_fallback() -> str | None:
    raw = query_database("SELECT email FROM users ORDER BY id")
    lines = [line.strip() for line in raw.splitlines() if line.strip()]
    if not lines or lines[0].startswith("Error:") or lines[0].startswith("SQL error:"):
        return None

    emails = []
    for line in lines[2:]:
        if EMAIL_RE.search(line):
            emails.append(line)

    if not emails:
        return None

    return "Here are all the email addresses in the users table:\n" + "\n".join(f"- {email}" for email in emails)


def _normalize_result(user_message: str, result_text: str) -> str:
    if not _looks_like_email_list_prompt(user_message):
        return result_text
    if EMAIL_RE.search(result_text or ""):
        return result_text
    fallback = _email_list_fallback()
    return fallback or result_text


@app.entrypoint
def invoke(payload: dict):
    """AgentCore entrypoint: run BarryBot with the given prompt."""
    if not isinstance(payload, dict):
        payload = {"prompt": str(payload)}
    user_message = payload.get("prompt", "Hello! How can I help you today?")
    clear_inspection_context()
    agentsec.set_metadata(
        src_app="barrybot-agentcore",
        client_transaction_id=str(payload.get("request_id") or uuid.uuid4()),
        agent_name=os.getenv("AGENTCORE_BARRYBOT_AGENT_NAME", "barrybot_agentcore"),
        deployment_type=os.getenv("AGENTCORE_DEPLOYMENT_TYPE", "direct_code_deploy"),
    )
    try:
        result = get_agent()(user_message)
        return {"result": _normalize_result(user_message, str(result))}
    except SecurityPolicyError as e:
        return _ai_defense_block_response(e.decision)
    except Exception as e:
        # Catch SecurityPolicyError from any import path or wrapper (has .decision)
        if hasattr(e, "decision") and e.decision is not None:
            return _ai_defense_block_response(e.decision)
        raise


if __name__ == "__main__":
    port = int(os.getenv("PORT", "8080"))
    print(f"Starting AgentCore BarryBot dev server on port {port}...")
    app.run(host="0.0.0.0", port=port)
