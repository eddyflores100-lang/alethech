#!/usr/bin/env python3
"""Minimal alethech hello world: init, commit, verify.

The smallest possible example that shows the core lifecycle:
  1. alethech init    — generate keypair + genesis commit
  2. alethech commit  — sign a memory commit
  3. alethech verify  — walk the DAG, verify all signatures

Run: python examples/hello_world.py
"""
import json
import tempfile
from pathlib import Path

from alethech.cli import cli
from click.testing import CliRunner


def main():
    runner = CliRunner()

    with tempfile.TemporaryDirectory(prefix="alethech-hello-") as tmp:
        store = Path(tmp) / "store"

        runner.invoke(cli, ["--store", str(store), "init"])

        content = Path(tmp) / "hello.json"
        content.write_text(json.dumps({"hello": "world"}))
        runner.invoke(cli, [
            "--store", str(store),
            "commit", "--content", str(content), "--type", "semantic",
        ])

        result = runner.invoke(cli, ["--store", str(store), "verify"])
        print(result.output.strip())


if __name__ == "__main__":
    main()
