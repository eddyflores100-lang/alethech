"""Real newline JSON-RPC subprocess tests for the local MCP memory bridge."""
import json
from pathlib import Path
import select
import subprocess
import sys

import pytest

from alethech.api import Alethech
from alethech.mcp_memory import MAX_REQUEST_BYTES, MemoryServer


@pytest.fixture
def memory(tmp_path):
    agent = Alethech.initialize(tmp_path / "store")
    agent.commit({"fact": "remember portable projects"})
    agent.commit({"preference": "concise answers"})
    path = agent.seal(tmp_path / "memory.aleth", "local-only-secret")
    credential = tmp_path / "secret.txt"
    credential.write_text("local-only-secret\n", encoding="utf-8")
    credential.chmod(0o600)
    return agent, path, credential


class Client:
    def __init__(self, path, credential):
        self.process = subprocess.Popen(
            [sys.executable, "-m", "alethech.mcp_memory", "--memory", str(path),
             "--passphrase-file", str(credential)],
            stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        )
        self.next_id = 0

    def raw(self, line):
        self.process.stdin.write(line)
        self.process.stdin.flush()
        ready, _, _ = select.select([self.process.stdout], [], [], 20)
        assert ready, "MCP response timed out"
        response = self.process.stdout.readline()
        assert response, "MCP process exited without a response"
        return json.loads(response)

    def request(self, method, params=None):
        self.next_id += 1
        request = {"jsonrpc": "2.0", "id": self.next_id, "method": method}
        if params is not None:
            request["params"] = params
        response = self.raw((json.dumps(request) + "\n").encode())
        assert response["id"] == self.next_id
        return response

    def call(self, name="alethech_memory_context", **arguments):
        return self.request("tools/call", {"name": name, "arguments": arguments})

    def close(self):
        self.process.stdin.close()
        self.process.wait(timeout=20)
        stderr = self.process.stderr.read()
        self.process.stdout.close()
        self.process.stderr.close()
        assert self.process.returncode == 0
        assert stderr == b""


@pytest.fixture
def client(memory):
    _, path, credential = memory
    process = Client(path, credential)
    yield process
    process.close()


def payload(response):
    result = response["result"]
    assert result["isError"] is False
    return json.loads(result["content"][0]["text"])


def test_initialize_list_context_and_verification(client, memory):
    agent, _, _ = memory
    for version in ("2024-11-05", "2025-03-26", "2025-06-18"):
        initialized = client.request("initialize", {"protocolVersion": version})
        assert initialized["result"]["protocolVersion"] == version
    assert client.request("initialize", {"protocolVersion": "unsupported"})["result"]["protocolVersion"] == "2025-06-18"
    client.process.stdin.write(b'{"jsonrpc":"2.0","method":"notifications/initialized"}\n')
    client.process.stdin.flush()
    tools = client.request("tools/list")["result"]["tools"]
    assert {tool["name"] for tool in tools} == {"alethech_memory_context", "alethech_memory_verify"}
    result = client.call()
    context = payload(result)
    assert context == agent.context()
    encoded = json.dumps(result)
    assert "local-only-secret" not in encoded
    assert "signing.key" not in encoded
    private_key = (agent.path / "keys" / "signing.key").read_text().strip()
    assert private_key not in encoded
    assert not {"keys", "identity", "public_key", "recovery_code", "passphrase"} & context.keys()
    assert payload(client.call(limit=1))["entries"] == context["entries"][-1:]
    verified = payload(client.call("alethech_memory_verify"))
    assert verified == {"verified": True, "head": agent.head, "entries_total": 2}


def test_rereads_current_file_and_credential(client, memory):
    agent, path, credential = memory
    first_head = payload(client.call())["head"]
    agent.commit({"fact": "newly saved memory"})
    agent.seal(path, "updated-local-secret")
    # It must not cache previously unlocked memory when the new file cannot unlock.
    assert client.call()["result"]["isError"] is True
    credential.write_text("updated-local-secret\n", encoding="utf-8")
    context = payload(client.call())
    assert context["head"] == agent.head != first_head
    assert context["entries"][-1]["content"] == {"fact": "newly saved memory"}


def test_bad_password_and_tampered_file_fail_closed(client, memory):
    _, path, credential = memory
    credential.write_text("WRONG-secret", encoding="utf-8")
    failed = client.call(limit=1)["result"]
    assert failed["isError"] is True
    assert failed["content"] == [{"type": "text", "text": "Memory unavailable or verification failed."}]
    credential.write_text("local-only-secret", encoding="utf-8")
    data = bytearray(path.read_bytes())
    data[-1] ^= 1
    path.write_bytes(data)
    assert client.call("alethech_memory_verify")["result"]["isError"] is True
    assert client.call(limit=1)["result"] == failed


@pytest.mark.parametrize("arguments", [
    {"path": "/etc/passwd"}, {"memory": "/etc/passwd"}, {"passphrase": "secret"},
    {"passphrase_file": "/etc/passwd"}, {"limit": True}, {"limit": 0},
    {"limit": -1}, {"limit": 1001}, {"limit": "1"}, {"limit": None},
])
def test_unknown_arguments_and_invalid_limits_rejected(client, arguments):
    response = client.request("tools/call", {"name": "alethech_memory_context", "arguments": arguments})
    assert response["error"]["code"] == -32602
    assert "/etc/passwd" not in json.dumps(response)
    assert "secret" not in json.dumps(response)


def test_rejects_invalid_arguments_before_any_reads(monkeypatch, tmp_path):
    server = MemoryServer(tmp_path / "missing", tmp_path / "missing-secret")
    def unexpected_read(*args, **kwargs):
        raise AssertionError("request attempted an arbitrary path read")
    monkeypatch.setattr(Path, "open", unexpected_read)
    result = server.handle({"jsonrpc": "2.0", "id": 1, "method": "tools/call",
                            "params": {"name": "alethech_memory_context", "arguments": {"path": "/etc/passwd"}}})
    assert result["error"]["code"] == -32602


def test_parse_errors_unknown_method_and_bounded_frames(client):
    assert client.raw(b'not-json\n')["error"]["code"] == -32700
    assert client.raw(b'[]\n')["error"]["code"] == -32600
    assert client.raw(b'{"jsonrpc":"2.0","id":true,"method":"ping"}\n')["error"]["code"] == -32600
    assert client.request("unknown")["error"]["code"] == -32601
    assert client.call("unknown")["error"]["code"] == -32602
    assert client.raw(b'x' * (MAX_REQUEST_BYTES + 10) + b'\n')["error"]["code"] == -32600
    assert client.request("ping")["result"] == {}


def test_limit_cannot_hide_invalid_history_outside_head(client, memory):
    # Construct authenticated encryption around an invalid signed store to test
    # signature/history verification independently of ciphertext authentication.
    from alethech.container import _collect, _seal_payload_bytes
    agent, path, _ = memory
    original_head = agent.head
    orphan = agent.commit({"fact": "unreachable branch"})
    agent.store.write_head(original_head)
    orphan.content = {"fact": "tampered unreachable branch"}
    agent.store.write_commit(orphan)
    forged = {"files": _collect(agent.path), "payload_version": 1}
    path.write_bytes(_seal_payload_bytes(forged, "local-only-secret"))
    response = client.call(limit=1)["result"]
    assert response["isError"] is True
    assert "concise answers" not in json.dumps(response)


def test_default_limit_and_oversized_output_fail_explicitly(monkeypatch, tmp_path):
    from alethech.mcp_memory import MAX_RESULT_BYTES
    server = MemoryServer(tmp_path / "memory.aleth", tmp_path / "secret.txt")
    context = {"format": "alethech-memory-view", "version": 1, "head": "sha256:test",
               "entries": [{"content": {"i": i}} for i in range(25)]}
    monkeypatch.setattr(server, "_context", lambda: context)
    request = {"jsonrpc": "2.0", "id": 1, "method": "tools/call",
               "params": {"name": "alethech_memory_context", "arguments": {}}}
    assert payload(server.handle(request))["entries"] == context["entries"][-20:]
    context["entries"][-1] = {"content": {"private_memory": "x" * MAX_RESULT_BYTES}}
    request["params"]["arguments"] = {"limit": 1}
    response = server.handle(request)["result"]
    assert response["isError"] is True
    assert "output limit" in response["content"][0]["text"]
    assert "private_memory" not in json.dumps(response)
