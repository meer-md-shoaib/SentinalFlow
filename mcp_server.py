"""SentinelFlow Model Context Protocol (MCP) Server.

Exposes SentinelFlow's autonomous cybersecurity investigation and response tools
over the standard Model Context Protocol (MCP) JSON-RPC 2.0 stdio interface.

This allows external AI orchestrators, Claude Desktop, Cursor, or any MCP client
to invoke SentinelFlow's SecOps capabilities alongside Fetch.ai's Agent Chat Protocol (ACP).

Dual Protocol Architecture:
- ACP (Agent Chat Protocol): Native Fetch.ai / ASI:One chat UI with interactive cards.
- MCP (Model Context Protocol): Standard tool integration for LLMs, Claude, and IDE agents.
"""

from __future__ import annotations

import json
import sys
from typing import Any

from controller import SentinelFlowController
from tools.simulated_response import verify_containment_state, execute_simulated_action

controller = SentinelFlowController()

TOOLS_DEFINITIONS = [
    {
        "name": "investigate_security_logins",
        "description": "Investigate security login telemetry, anomaly detection, risk scoring (0-100), and MITRE ATT&CK mapping for a target user ID, email address, or IP.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "target": {
                    "type": "string",
                    "description": "Target identity: user ID (e.g. demo-user-104), consumer email (e.g. alex@gmail.com), or IP address",
                },
                "time_window_minutes": {
                    "type": "integer",
                    "default": 60,
                    "description": "Time window in minutes to search telemetry (default: 60)",
                },
            },
            "required": ["target"],
        },
    },
    {
        "name": "emergency_account_lockdown",
        "description": "Execute human-approved containment response (session revocation or IP block) with simulated Fetch.ai 0.1 FET escrow settlement and cryptographic verification.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "target": {
                    "type": "string",
                    "description": "Target user ID, email, or IP to contain",
                },
                "action_type": {
                    "type": "string",
                    "enum": ["revoke_user_sessions", "block_ip_address", "isolate_endpoint"],
                    "default": "revoke_user_sessions",
                    "description": "Type of containment action",
                },
                "approval_token": {
                    "type": "string",
                    "default": "APPROVED_BY_ANALYST",
                    "description": "Human-in-the-loop authorization token",
                },
            },
            "required": ["target"],
        },
    },
    {
        "name": "verify_containment_proof",
        "description": "Verify cryptographic SHA-256 state proof of containment action to prove closed-loop execution and tamper-evident remediation.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "action_id": {
                    "type": "string",
                    "description": "Unique containment action ID (e.g. act-demo-user-104-revoke_user_sessions)",
                },
                "target": {
                    "type": "string",
                    "description": "Target identity verified",
                },
            },
            "required": ["action_id", "target"],
        },
    },
]


def handle_tool_call(name: str, arguments: dict[str, Any]) -> dict[str, Any]:
    """Execute SentinelFlow tool and return standard MCP tool content."""
    if name == "investigate_security_logins":
        target = str(arguments.get("target", "demo-user-104"))
        time_window = int(arguments.get("time_window_minutes", 60))
        result = controller.process_investigation_request(
            intent="investigate_suspicious_logins",
            target=target,
            time_window_minutes=time_window,
        )
        return {
            "content": [
                {
                    "type": "text",
                    "text": json.dumps(result, indent=2, default=str),
                }
            ],
            "isError": result.get("status") == "failed",
        }

    elif name == "emergency_account_lockdown":
        target = str(arguments.get("target", "demo-user-104"))
        action_type = str(arguments.get("action_type", "revoke_user_sessions"))
        token = str(arguments.get("approval_token", "APPROVED_BY_ANALYST"))
        result = controller.process_investigation_request(
            intent="request_containment",
            target=target,
            requested_action=action_type,
            approval_token=token,
        )
        return {
            "content": [
                {
                    "type": "text",
                    "text": json.dumps(result, indent=2, default=str),
                }
            ],
            "isError": result.get("status") == "failed",
        }

    elif name == "verify_containment_proof":
        action_id = str(arguments.get("action_id", ""))
        expected = str(arguments.get("expected_status", "sessions_revoked"))
        # Auto-detect expected status from stored action type if present
        store = controller.state_store
        record = store.action_ledger.get(action_id)
        if record:
            act_type = record.get("action_type")
            if act_type == "revoke_user_sessions":
                expected = "sessions_revoked"
            elif act_type == "block_ip_address":
                expected = "blocked"
            elif act_type == "isolate_endpoint":
                expected = "isolated"
        verification = verify_containment_state(action_id=action_id, expected_status=expected)
        return {
            "content": [
                {
                    "type": "text",
                    "text": json.dumps(verification, indent=2, default=str),
                }
            ],
            "isError": not verification.get("verified", False),
        }

    else:
        return {
            "content": [
                {
                    "type": "text",
                    "text": f"Unknown tool: '{name}'",
                }
            ],
            "isError": True,
        }


def process_jsonrpc_message(msg: dict[str, Any]) -> dict[str, Any] | None:
    """Process a single JSON-RPC 2.0 message according to MCP specification."""
    msg_id = msg.get("id")
    method = msg.get("method")
    params = msg.get("params", {})

    # 1. Initialize
    if method == "initialize":
        return {
            "jsonrpc": "2.0",
            "id": msg_id,
            "result": {
                "protocolVersion": "2024-11-05",
                "capabilities": {
                    "tools": {
                        "listChanged": False,
                    }
                },
                "serverInfo": {
                    "name": "sentinelflow-secops-mcp",
                    "version": "1.0.0",
                },
            },
        }

    # 2. Notification: initialized (no response required by JSON-RPC)
    if method in ("notifications/initialized", "initialized"):
        return None

    # 3. Ping
    if method == "ping":
        return {
            "jsonrpc": "2.0",
            "id": msg_id,
            "result": {},
        }

    # 4. List Tools
    if method == "tools/list":
        return {
            "jsonrpc": "2.0",
            "id": msg_id,
            "result": {
                "tools": TOOLS_DEFINITIONS,
            },
        }

    # 5. Call Tool
    if method == "tools/call":
        tool_name = params.get("name", "")
        args = params.get("arguments", {})
        call_result = handle_tool_call(tool_name, args)
        return {
            "jsonrpc": "2.0",
            "id": msg_id,
            "result": call_result,
        }

    # Method not found
    if msg_id is not None:
        return {
            "jsonrpc": "2.0",
            "id": msg_id,
            "error": {
                "code": -32601,
                "message": f"Method not found: {method}",
            },
        }
    return None


def run_stdio_server():
    """Run MCP server reading JSON-RPC lines from sys.stdin and writing to sys.stdout."""
    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue
        try:
            req = json.loads(line)
            resp = process_jsonrpc_message(req)
            if resp is not None:
                sys.stdout.write(json.dumps(resp) + "\n")
                sys.stdout.flush()
        except Exception as exc:
            err_resp = {
                "jsonrpc": "2.0",
                "id": None,
                "error": {
                    "code": -32700,
                    "message": f"Parse error or unhandled exception: {exc}",
                },
            }
            sys.stdout.write(json.dumps(err_resp) + "\n")
            sys.stdout.flush()


if __name__ == "__main__":
    run_stdio_server()
