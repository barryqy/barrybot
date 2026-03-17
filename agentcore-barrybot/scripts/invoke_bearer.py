#!/usr/bin/env python3
"""Invoke BarryBot on Bedrock AgentCore using AWS_BEARER_TOKEN_BEDROCK.

Use this when your environment authenticates to Bedrock/AgentCore with a bearer token
instead of (or in addition to) AWS credentials.

  export AWS_BEARER_TOKEN_BEDROCK=your-token
  export AGENTCORE_AGENT_ARN=arn:aws:bedrock-agentcore:us-west-2:123456789012:...
  export AGENTCORE_SESSION_ID=session-$(uuidgen)   # or from .bedrock_agentcore.yaml
  python scripts/invoke_bearer.py "List all user emails"

If AGENTCORE_INVOKE_URL is set (e.g. an API Gateway that accepts Bearer and forwards
to AgentCore), we POST there. Otherwise we use boto3 with standard AWS auth and
optionally inject the bearer token in a custom header if your setup expects it.
"""

import json
import os
import sys
import uuid
from pathlib import Path


def read_runtime_payload(response: dict):
    raw = response.get("payload") or response.get("response")
    if raw is None:
        print(f"Unexpected response keys: {list(response.keys())}", file=sys.stderr)
        sys.exit(1)

    if hasattr(raw, "read"):
        body = raw.read()
    else:
        body = raw

    if isinstance(body, bytes):
        body = body.decode("utf-8")

    try:
        return json.loads(body)
    except json.JSONDecodeError:
        return body


def main():
    prompt = " ".join(sys.argv[1:]) if len(sys.argv) > 1 else "List all user email addresses"
    payload = json.dumps({"prompt": prompt}).encode("utf-8")

    bearer = os.environ.get("AWS_BEARER_TOKEN_BEDROCK")
    invoke_url = os.environ.get("AGENTCORE_INVOKE_URL")

    if bearer and invoke_url:
        # Direct HTTPS with Bearer token (e.g. API Gateway in front of AgentCore)
        import urllib.request
        req = urllib.request.Request(
            invoke_url,
            data=payload,
            method="POST",
            headers={
                "Content-Type": "application/json",
                "Accept": "application/json",
                "Authorization": f"Bearer {bearer}",
            },
        )
        with urllib.request.urlopen(req, timeout=60) as resp:
            body = resp.read().decode()
            print(body)
        return

    # Fallback: boto3 (uses AWS credentials; bearer not used by AWS API directly)
    region = os.environ.get("AWS_REGION", "us-west-2")
    root = Path(__file__).resolve().parent.parent
    config_file = root / ".bedrock_agentcore.yaml"
    agent_arn = os.environ.get("AGENTCORE_AGENT_ARN")
    session_id = os.environ.get("AGENTCORE_SESSION_ID")

    if not agent_arn or not session_id:
        if config_file.exists():
            try:
                import yaml
                with open(config_file) as f:
                    cfg = yaml.safe_load(f)
                agents = cfg.get("agents", {})
                name = os.environ.get("AGENTCORE_BARRYBOT_AGENT_NAME", "barrybot_agentcore")
                fallback_name = next(iter(agents), None)
                agent_cfg = agents.get(name) or (agents.get(fallback_name) if fallback_name else None)
                if agent_cfg:
                    bc = agent_cfg.get("bedrock_agentcore", {})
                    agent_arn = agent_arn or bc.get("agent_arn")
                    session_id = session_id or bc.get("agent_session_id")
            except Exception:
                pass
        if not session_id:
            session_id = f"session-{uuid.uuid4().hex[:32]}"

    if not agent_arn:
        print("Set AGENTCORE_AGENT_ARN or run deploy.sh and use .bedrock_agentcore.yaml", file=sys.stderr)
        sys.exit(1)

    import boto3
    client = boto3.client("bedrock-agentcore", region_name=region)
    resp = client.invoke_agent_runtime(
        agentRuntimeArn=agent_arn,
        runtimeSessionId=session_id,
        payload=payload,
    )
    result = read_runtime_payload(resp)
    if isinstance(result, dict):
        print(result.get("result", result))
    else:
        print(result)


if __name__ == "__main__":
    main()
