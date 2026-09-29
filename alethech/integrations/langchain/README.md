# alethech — LangChain Integration

Sign every LangChain LLM interaction with Ed25519 using alethech.

## Install

```bash
pip install alethech langchain
```

## Quick start

```python
from alethech.integrations.langchain import AlethechCallbackHandler
from langchain_openai import ChatOpenAI

# Initialize alethech store
handler = AlethechCallbackHandler(store_path="~/.alethech")

# Use as callback in LangChain
llm = ChatOpenAI(callbacks=[handler])

# Every call is now signed and stored
response = llm.invoke("What is Ed25519?")

# Verify all interactions are intact
assert handler.verify()  # True if all signatures valid
```

## What gets signed

Each LLM call produces:
1. **MemoryCommit** — prompt, model name, response length
2. **EvidenceCommit** — input/output SHA-256 hashes, tool name

Both are Ed25519-signed and linked in the Merkle DAG.

MIT License.
