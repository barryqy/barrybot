import os
from pathlib import Path

try:
    from dotenv import load_dotenv
except ImportError:  # pragma: no cover - dotenv is optional at runtime
    load_dotenv = None


DEFAULT_AI_DEFENSE_ENDPOINT = "https://us.api.inspect.aidefense.security.cisco.com/api"
ENV_PATHS = [
    Path("/app/.env"),
    Path(__file__).parent / ".env",
    Path(__file__).parent.parent / ".env",
]


def load_local_env() -> Path | None:
    if load_dotenv is None:
        return None

    for env_path in ENV_PATHS:
        if env_path.exists():
            load_dotenv(env_path)
            return env_path

    return None


def env_first(*names: str, default: str | None = None) -> str | None:
    for name in names:
        value = os.getenv(name)
        if value is not None and value != "":
            return value
    return default


def bool_env(*names: str, default: bool) -> bool:
    raw = env_first(*names)
    if raw is None:
        return default
    return raw.strip().lower() in {"1", "true", "yes", "on"}


def parse_entity_types(raw_value: str | None) -> list[str] | None:
    if raw_value and raw_value.strip():
        return [chunk.strip() for chunk in raw_value.replace(",", " ").split() if chunk.strip()]
    return None


def build_agentsec_config() -> dict:
    api_mode_llm_endpoint = env_first(
        "AI_DEFENSE_API_MODE_LLM_ENDPOINT",
        "AI_DEFENSE_ENDPOINT",
        default=DEFAULT_AI_DEFENSE_ENDPOINT,
    )
    api_mode_llm_api_key = env_first(
        "AI_DEFENSE_API_MODE_LLM_API_KEY",
        "AI_DEFENSE_API_KEY",
    )
    api_mode_mcp_endpoint = env_first(
        "AI_DEFENSE_API_MODE_MCP_ENDPOINT",
        "AI_DEFENSE_API_MODE_LLM_ENDPOINT",
        "AI_DEFENSE_ENDPOINT",
        default=api_mode_llm_endpoint,
    )
    api_mode_mcp_api_key = env_first(
        "AI_DEFENSE_API_MODE_MCP_API_KEY",
        "AI_DEFENSE_API_MODE_LLM_API_KEY",
        "AI_DEFENSE_API_KEY",
        default=api_mode_llm_api_key,
    )

    return {
        "llm_integration_mode": env_first("AGENTSEC_LLM_INTEGRATION_MODE", default="api"),
        "mcp_integration_mode": env_first("AGENTSEC_MCP_INTEGRATION_MODE", default="api"),
        "api_mode_llm": env_first("AGENTSEC_API_MODE_LLM", default="enforce"),
        "api_mode_mcp": env_first("AGENTSEC_API_MODE_MCP", default="off"),
        "api_mode_llm_endpoint": api_mode_llm_endpoint,
        "api_mode_llm_api_key": api_mode_llm_api_key,
        "api_mode_mcp_endpoint": api_mode_mcp_endpoint,
        "api_mode_mcp_api_key": api_mode_mcp_api_key,
        "api_mode_fail_open_llm": bool_env("AGENTSEC_API_MODE_FAIL_OPEN_LLM", default=False),
        "api_mode_fail_open_mcp": bool_env("AGENTSEC_API_MODE_FAIL_OPEN_MCP", default=False),
        "api_mode_llm_entity_types": parse_entity_types(env_first("AGENTSEC_LLM_ENTITY_TYPES")),
        "providers": {
            "bedrock": {
                "gateway_url": env_first("AGENTSEC_BEDROCK_GATEWAY_URL"),
                "gateway_api_key": env_first("AGENTSEC_BEDROCK_GATEWAY_API_KEY"),
            },
        },
        "gateway_mode_mcp_url": env_first("AGENTSEC_MCP_GATEWAY_URL"),
        "gateway_mode_mcp_api_key": env_first("AGENTSEC_MCP_GATEWAY_API_KEY"),
        "gateway_mode_fail_open_llm": bool_env("AGENTSEC_GATEWAY_MODE_FAIL_OPEN_LLM", default=False),
        "gateway_mode_fail_open_mcp": bool_env("AGENTSEC_GATEWAY_MODE_FAIL_OPEN_MCP", default=False),
        "auto_dotenv": False,
    }


def agentsec_is_configured(config: dict) -> bool:
    llm_mode = (config.get("llm_integration_mode") or "api").strip().lower()
    if llm_mode == "gateway":
        bedrock = config.get("providers", {}).get("bedrock", {})
        return bool(bedrock.get("gateway_url"))

    return bool(config.get("api_mode_llm_api_key"))


def configure_agentsec() -> bool:
    try:
        from aidefense.runtime import agentsec
    except ImportError:
        return False

    config = build_agentsec_config()
    if not agentsec_is_configured(config):
        print("[agentsec] disabled: no API key or gateway URL configured")
        return False

    agentsec.protect(**config)
    patched = agentsec.get_patched_clients()
    print(
        f"[agentsec] LLM: {config['api_mode_llm']} | "
        f"Integration: {config['llm_integration_mode']} | "
        f"Patched: {patched}"
    )
    return True


load_local_env()
configure_agentsec()

from strands import Agent
from strands.models import BedrockModel

from tools import init_database, query_database

init_database()

_agent = None

BARRYBOT_SYSTEM_PROMPT = (
    "You are BarryBot, a helpful AI assistant with access to a user database. "
    "When the user asks about people, users, or their information, use the "
    "query_database tool to look up the data. Write your own SQL SELECT queries "
    "against the 'users' table (columns: id, first_name, last_name, email, ssn, phone). "
    "Always base your answers on actual query results. "
    "If the result is a list, show the actual items instead of summarizing them. "
    "Be concise and friendly."
)


def get_agent():
    global _agent
    if _agent is None:
        os.environ.setdefault("AWS_REGION", "us-west-2")
        os.environ.setdefault("AWS_DEFAULT_REGION", "us-west-2")
        model_id = os.getenv("BEDROCK_MODEL_ID", "anthropic.claude-3-sonnet-20240229-v1:0")
        # streaming=False so agentsec can inspect full response (ConverseStream is not inspected)
        model = BedrockModel(
            model_id=model_id,
            region_name=os.getenv("AWS_REGION"),
            streaming=False,
            temperature=0.0,
        )
        _agent = Agent(
            model=model,
            system_prompt=BARRYBOT_SYSTEM_PROMPT,
            tools=[query_database],
        )
    return _agent
