"""Unit tests for SentinelFlow Model Context Protocol (MCP) Server (T14)."""

import json
import pytest
from mcp_server import process_jsonrpc_message
from tools.simulated_response import reset_state_store


@pytest.fixture(autouse=True)
def clean_state():
    reset_state_store()


def test_mcp_initialize_and_ping():
    """Validate MCP initialize handshake and ping per MCP 2024-11-05 spec."""
    init_req = {
        "jsonrpc": "2.0",
        "id": 1,
        "method": "initialize",
        "params": {
            "protocolVersion": "2024-11-05",
            "clientInfo": {"name": "claude-desktop", "version": "1.0.0"},
            "capabilities": {},
        },
    }
    init_resp = process_jsonrpc_message(init_req)
    assert init_resp is not None
    assert init_resp["id"] == 1
    assert init_resp["result"]["protocolVersion"] == "2024-11-05"
    assert "tools" in init_resp["result"]["capabilities"]
    assert init_resp["result"]["serverInfo"]["name"] == "sentinelflow-secops-mcp"

    ping_req = {"jsonrpc": "2.0", "id": 2, "method": "ping"}
    ping_resp = process_jsonrpc_message(ping_req)
    assert ping_resp == {"jsonrpc": "2.0", "id": 2, "result": {}}


def test_mcp_tools_list():
    """Validate that SentinelFlow exports its 3 core SecOps tools with schemas."""
    list_req = {"jsonrpc": "2.0", "id": 3, "method": "tools/list"}
    list_resp = process_jsonrpc_message(list_req)
    assert list_resp is not None
    tools = list_resp["result"]["tools"]
    tool_names = [t["name"] for t in tools]
    assert "investigate_security_logins" in tool_names
    assert "emergency_account_lockdown" in tool_names
    assert "verify_containment_proof" in tool_names


def test_mcp_tools_call_investigate():
    """Validate executing investigate_security_logins via MCP JSON-RPC."""
    call_req = {
        "jsonrpc": "2.0",
        "id": 4,
        "method": "tools/call",
        "params": {
            "name": "investigate_security_logins",
            "arguments": {"target": "demo-user-104", "time_window_minutes": 60},
        },
    }
    call_resp = process_jsonrpc_message(call_req)
    assert call_resp is not None
    assert call_resp["id"] == 4
    content = call_resp["result"]["content"]
    assert len(content) > 0
    assert content[0]["type"] == "text"
    payload = json.loads(content[0]["text"])
    assert payload["risk_level"] in ("high", "critical")
    assert payload["risk_score"] >= 80
    assert len(payload["evidence"]) >= 1


def test_mcp_tools_call_lockdown_and_verify():
    """Validate executing containment lockdown and cryptographic verification via MCP."""
    lock_req = {
        "jsonrpc": "2.0",
        "id": 5,
        "method": "tools/call",
        "params": {
            "name": "emergency_account_lockdown",
            "arguments": {
                "target": "demo-user-104",
                "action_type": "revoke_user_sessions",
                "approval_token": "APPROVED_BY_ANALYST",
            },
        },
    }
    lock_resp = process_jsonrpc_message(lock_req)
    assert lock_resp is not None
    lock_payload = json.loads(lock_resp["result"]["content"][0]["text"])
    assert lock_payload["status"] == "completed"
    action_id = lock_payload["action"]["action_id"]

    # Now verify proof via MCP
    verify_req = {
        "jsonrpc": "2.0",
        "id": 6,
        "method": "tools/call",
        "params": {
            "name": "verify_containment_proof",
            "arguments": {
                "action_id": action_id,
                "target": "demo-user-104",
            },
        },
    }
    verify_resp = process_jsonrpc_message(verify_req)
    assert verify_resp is not None
    verify_payload = json.loads(verify_resp["result"]["content"][0]["text"])
    assert verify_payload["verified"] is True
    assert "audit_hash" in verify_payload
    assert len(verify_payload["audit_hash"]) == 64  # SHA-256


def test_mcp_unknown_method_and_tool():
    """Validate error handling for nonexistent methods and tools."""
    bad_method = {"jsonrpc": "2.0", "id": 7, "method": "nonexistent_method"}
    bad_resp = process_jsonrpc_message(bad_method)
    assert bad_resp is not None
    assert "error" in bad_resp
    assert bad_resp["error"]["code"] == -32601

    bad_tool = {
        "jsonrpc": "2.0",
        "id": 8,
        "method": "tools/call",
        "params": {"name": "fake_tool", "arguments": {}},
    }
    bad_tool_resp = process_jsonrpc_message(bad_tool)
    assert bad_tool_resp is not None
    assert bad_tool_resp["result"]["isError"] is True
