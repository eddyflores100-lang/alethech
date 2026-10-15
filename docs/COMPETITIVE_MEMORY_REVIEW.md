# Agent memory comparison — 2026-10-15

This is a documentation comparison, not a benchmark or proof that one product is universally better. Sources below are primary project documentation retrieved on 2026-10-15. Features, pricing and installation paths can change.

| Alternative | What its documentation offers | Setup / operational trade-off | What Alethech should learn |
|---|---|---|---|
| Supermemory MCP | Managed cross-client memory, search/save, project spaces, OAuth sign-in with no API key | Remote endpoint and account; self-hosting is another option | A simple first run matters. Do not market "no API key" as unique. Keep project boundaries explicit. |
| Mem0 self-hosted server | Memory CRUD, dashboard, per-user keys, audit log | Reference setup uses Docker Compose, LLM/embedder provider config, secrets and a database | Keep structured memories and provenance while avoiding server configuration in the portable skill. This describes the server setup, not every Mem0 configuration. |
| MCP Memory Service | Local embeddings, multiple storage backends, MCP/HTTP/REST, lifecycle tools and integrations | A running service; optional remote/cloud configurations | Local/no-API memory is established. Differentiate on a transferable encrypted artifact and a small surface, not unsupported retrieval superiority. |
| Hindsight | Retain/recall/reflect, agent integrations, automatic coding-agent ingestion, memory banks and built-in MCP | A memory runtime/server or embedded integration; different deployment choices | Give agents a clear resume/save ritual and confirmed next steps, without importing a large cognitive subsystem. |
| MemPalace | Local retrieval, agent knowledge structures, autosave hooks and transcript ingestion | Its documented defaults include a vector backend and embedding-model storage | Verbatim records and session handoffs help. Do not add mandatory model downloads just for basic continuity. |
| Agent Skills ecosystem | Portable SKILL.md folders with executable resources, many supported hosts and a standard CLI | The host must actually load skills and support the resources they require | Distribute the complete skill folder; distinguish installing instructions from granting filesystem access. |

## Product decision

Build a portable memory passport around the existing signed DAG and encrypted `.aleth`. The first local save creates a usable memory automatically. An agent can resume from a bounded verified handoff rather than flooding its context with a transcript. Cloud is an optional encrypted file copy into a sync folder the user already has; no cloud credentials or connector configuration are needed.

The differentiator is the combination: independent encrypted file + verified causal history + script-capable Agent Skill + project isolation + explicit handoff + bounded recall + conflict-preserving backup. This is a product design choice, not a claim of novelty over every memory project. There are no measured retrieval/latency superiority claims here.

## Agent pain points and implemented responses

| Pain | Response | Remaining limit |
|---|---|---|
| Starts again after context reset | Save goals, verified work, decisions, constraints, next steps, open questions | The host must invoke the skill; there is no universal background hook |
| Hallucinates missing history | Verify all history before recall; expose citations and omitted count | Signed text may still contain false claims |
| Uses old or mixed project context | Explicit spaces, per-space identity, local HEAD checkpoint | No trusted external checkpoint on first import |
| Runs instructions found inside memory | Mark all content as untrusted data and instruct the consuming agent to quote rather than execute | A skill is not a model sandbox |
| Leaks tokens/keys | Avoid secret arguments and output; filter common credential shapes before save | Pattern detection cannot find every secret; same-user agents can read local files |
| Loses edits during syncing | Lock local writes, compare source before replacing, compare cloud digest, preserve changed cloud revision | Ordinary sync folders do not offer distributed atomic writes |
| Needs too much setup | First local save is automatic; isolate missing protocol dependencies once | Python/script execution required; first dependency download needs network |
| Cannot transfer providers | `.aleth` export/import and existing offline viewer/text fallback | Browser-only chats cannot decrypt arbitrary attachments without a bridge |

## Sources

- Supermemory: https://supermemory.ai/mcp/ (current managed OAuth/no-key flow; older docs describe a different setup).
- Mem0 server: https://github.com/mem0ai/mem0/blob/main/docs/open-source/setup.mdx
- MCP Memory Service: https://github.com/doobidoo/mcp-memory-service/blob/main/README.md
- Hindsight: https://github.com/vectorize-io/hindsight
- MemPalace: https://github.com/MemPalace/mempalace and https://mempalaceofficial.com/guide/getting-started
- Agent Skills specification: https://agentskills.io/specification
- Skills CLI: https://github.com/vercel-labs/skills
