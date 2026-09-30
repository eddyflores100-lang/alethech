"""Minimal programmatic alethech integration: no CLI runner."""
import tempfile
from pathlib import Path
from alethech.api import Alethech

with tempfile.TemporaryDirectory(prefix="alethech-api-") as tmp:
    agent = Alethech.initialize(Path(tmp) / "store")
    commit = agent.commit({"event": "agent learned a durable fact", "value": 42})
    report = agent.verify()
    print(f"commit={commit.commit_id}")
    print(f"head={agent.head}")
    print(f"verified={report.ok}")
