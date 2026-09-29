"""LangChain integration example for alethech.

This module shows how to use alethech as a callback handler in LangChain
to sign every LLM interaction with Ed25519, creating a verifiable
provenance trail of all agent actions.

Install:
    pip install alethech langchain

Usage:
    from alethech.integrations.langchain import AlethechCallbackHandler
    from langchain_openai import ChatOpenAI

    handler = AlethechCallbackHandler(store_path="~/.alethech")
    llm = ChatOpenAI(callbacks=[handler])
    llm.invoke("What is Ed25519?")
"""
from __future__ import annotations

from pathlib import Path
from typing import Any, Optional

from alethech import crypto
from alethech.objects import MemoryCommit, EvidenceCommit
from alethech.store import Store, StoreError


class AlethechCallbackHandler:
    """LangChain callback handler that signs every interaction with alethech.

    Creates a MemoryCommit for each LLM call with:
    - The prompt as content
    - The response as evidence
    - Ed25519 signature proving the agent produced it

    Usage:
        handler = AlethechCallbackHandler(store_path="~/.alethech")
        llm = ChatOpenAI(callbacks=[handler])
    """

    def __init__(self, store_path: str = "~/.alethech") -> None:
        path = Path(store_path).expanduser()
        try:
            self.store = Store.open(path)
        except StoreError:
            self.store = Store.init(path)
        self._last_prompt: str = ""

    def on_llm_start(
        self, serialized: dict, prompts: list[str], **kwargs: Any
    ) -> None:
        """Called when LLM starts. Store the prompt."""
        self._last_prompt = prompts[0] if prompts else ""

    def on_llm_end(self, response: Any, **kwargs: Any) -> None:
        """Called when LLM finishes. Sign the interaction."""
        # Extract response text
        try:
            output = response.generations[0][0].text
        except (IndexError, AttributeError):
            output = str(response)

        # Create a MemoryCommit with the interaction
        content = {
            "type": "llm_interaction",
            "prompt": self._last_prompt[:1000],  # truncate for storage
            "model": kwargs.get("model_name", "unknown"),
        }

        commit = MemoryCommit(
            agent_id=self._get_agent_id(),
            key_id="key-001",
            parents=[self.store.read_head() or ""],
            content=content,
            provenance={
                "integration": "langchain",
                "response_length": len(output),
            },
        )

        # Sign and store
        try:
            signing = self.store.load_signing_key()
            commit.sign(signing)
            self.store.write_commit(commit)

            # Also create evidence with the output
            ev = EvidenceCommit(
                agent_id=commit.agent_id,
                key_id="key-001",
                tool="langchain_llm",
                input_hash="sha256:" + crypto.sha256_hex(
                    self._last_prompt.encode()
                ),
                output_hash="sha256:" + crypto.sha256_hex(output.encode()),
                artifacts=[],
                result="success",
            )
            ev.sign(signing)
            self.store.write_evidence(ev)
        except StoreError:
            pass  # don't crash the LLM call if signing fails

    def on_chain_start(
        self, serialized: dict, inputs: dict, **kwargs: Any
    ) -> None:
        pass

    def on_chain_end(self, outputs: dict, **kwargs: Any) -> None:
        pass

    def on_tool_start(
        self, serialized: dict, input_str: str, **kwargs: Any
    ) -> None:
        pass

    def on_tool_end(self, output: str, **kwargs: Any) -> None:
        """Called when a tool finishes. Create evidence."""
        try:
            signing = self.store.load_signing_key()
            ev = EvidenceCommit(
                agent_id=self._get_agent_id(),
                key_id="key-001",
                tool=serialized.get("name", "unknown_tool"),
                input_hash="sha256:" + crypto.sha256_hex(
                    input_str.encode()
                ),
                output_hash="sha256:" + crypto.sha256_hex(output.encode()),
                artifacts=[],
                result="success",
            )
            ev.sign(signing)
            self.store.write_evidence(ev)
        except (StoreError, Exception):
            pass

    def _get_agent_id(self) -> str:
        """Get the agent_id from the store."""
        try:
            identities = self.store.load_identities()
            if identities:
                return next(iter(identities.values())).agent_id
        except Exception:
            pass
        return "did:alethech:unknown"

    def verify(self) -> bool:
        """Verify the store — all signatures valid?"""
        from alethech.verify import verify_store

        report = verify_store(self.store)
        return report.ok
