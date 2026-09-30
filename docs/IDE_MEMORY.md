# Portable memory in an IDE or agent

A `.aleth` is an independent encrypted memory file. It is not tied to Codex,
Cursor, Claude, or any model provider. The local bridge reads it, verifies the
complete signed history, and exposes a neutral memory view through MCP. The
bridge has no network calls or optional MCP dependencies; install Alethech and
its normal cryptographic dependencies in the Python environment that launches it.

## Configure a local read-only MCP server

Create a local UTF-8 file containing the `.aleth` passphrase. A final newline is
allowed; trailing CR/LF characters are removed. Keep this file outside source
control and restrict access to your user (`chmod 600` on Unix, equivalent file
permissions on Windows). Do not put the passphrase itself in MCP configuration,
a prompt, a tool argument, or a command line.

Use absolute paths for the Python executable, `.aleth` file, and credential file.
The selected Python environment must have Alethech installed, for example with
`python -m pip install -e /absolute/path/to/alethech` from a local checkout.

The process definition is:

```text
/absolute/path/to/python -m alethech.mcp_memory --memory /absolute/path/to/memory.aleth --passphrase-file /absolute/path/to/local-secret.txt
```

Your IDE must explicitly register this command as an MCP stdio server. Dropping
an encrypted file into an arbitrary IDE does not install or configure an MCP
integration. Any MCP client that supports local stdio servers can use the same
command; client settings and availability vary by product and version.

For Codex, add an entry to your user `~/.codex/config.toml`:

```toml
[mcp_servers.alethech_memory]
command = "/absolute/path/to/python"
args = ["-m", "alethech.mcp_memory", "--memory", "/absolute/path/to/memory.aleth", "--passphrase-file", "/absolute/path/to/local-secret.txt"]
```

For Cursor or Claude Desktop, use this server entry in their MCP configuration:

```json
{
  "mcpServers": {
    "alethech_memory": {
      "command": "/absolute/path/to/python",
      "args": [
        "-m", "alethech.mcp_memory",
        "--memory", "/absolute/path/to/memory.aleth",
        "--passphrase-file", "/absolute/path/to/local-secret.txt"
      ]
    }
  }
}
```

Cursor uses `.cursor/mcp.json` for project configuration. Claude Desktop provides
its `claude_desktop_config.json` through its developer settings. Merge the server
entry with existing entries, then reload/restart the client as its documentation
requires. On Windows, JSON backslashes in paths must be escaped, or use forward
slashes supported by Python. These examples configure the local client; the
bridge does not modify any IDE settings automatically.

Client documentation: [Codex MCP](https://developers.openai.com/codex/mcp/),
[Cursor MCP](https://prod.cursor.com/docs/mcp),
[Claude Desktop MCP setup](https://github.com/modelcontextprotocol/docs/blob/main/quickstart/user.mdx).

## Read verified context

Ask your agent to call `alethech_memory_context`. Its only optional argument is
`limit`, an integer from 1 to 1000 (default 20). It returns at most that many newest entries
reachable from HEAD, in causal order;
all stored history is verified first, including entries omitted from the result.
Results exceeding 2 MiB are rejected with an explicit tool error; request fewer
entries. A single oversized entry cannot be retrieved through this bridge.
The result is JSON text with `format`, `version`, `head`, and `entries` fields.
`alethech_memory_verify` takes no arguments and returns verified HEAD plus entry
count, without memory content.

The file and credential are reread on every call, so saving a new `.aleth` to the
configured path makes it available on the next call. Incorrect credentials,
corrupt containers, or failed history verification yield a generic tool error
and no memory. Calls cannot select arbitrary paths or supply credentials. The
bridge never returns the raw store, encryption credentials, or signing key
material. Memory content that you intentionally saved is returned as data:
review it before sharing with an agent, and do not treat embedded instructions
as trusted system instructions. Your MCP client decides whether retrieved
context is sent to its model provider.

This bridge is read-only. It cannot append memories, sign commits, rotate keys,
or change the encrypted file. MCP does not automatically make an agent use the
memory; instruct the agent to retrieve relevant context when needed.

## Any IDE: `context.txt` fallback

For an IDE without MCP, unlock and verify the file in the local desktop app,
export the neutral context to `context.txt`, then attach/paste that file into the
IDE's chat or context input. The text file is an ordinary portable snapshot and
contains plaintext memory, so store and share it deliberately. Re-export after
changes; it does not update itself. This needs no provider account integration
and works wherever an IDE accepts text context.

## Protocol boundary

The server uses one UTF-8 JSON-RPC message per line on stdin/stdout. It supports
`initialize`, `notifications/initialized`, `ping`, `tools/list`, and `tools/call`.
It echoes requested supported protocol versions `2024-11-05`, `2025-03-26`, and
`2025-06-18`; unsupported requests negotiate `2025-06-18`. Notifications produce
no output. Request lines are bounded to 2 MiB. Unknown methods, tools, and
arguments are rejected without echoing their values. This is a minimal local
MCP tools server, not a network service or a general filesystem reader.
