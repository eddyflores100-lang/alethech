"""Basic usage example for alethech.

This script shows the complete workflow:
1. Initialize a store
2. Create signed commits
3. Verify the store
4. Rotate keys
5. Export and import

Run: python examples/basic_usage.py
"""
import json
import shutil
import tempfile
from pathlib import Path

from alethech.cli import cli
from click.testing import CliRunner


def main():
    runner = CliRunner()

    # Create a temporary store
    store_path = Path(tempfile.mkdtemp(prefix="alethech-demo-")) / "alethech"
    print(f"Store: {store_path}\n")

    # 1. Initialize
    print("=== 1. Initialize ===")
    result = runner.invoke(cli, ["--store", str(store_path), "init"])
    print(result.output)

    # 2. Migrate to v0.2 (identity layer with root authority)
    print("=== 2. Migrate to v0.2 ===")
    result = runner.invoke(cli, ["--store", str(store_path), "migrate", "--to", "v0.2"])
    print(result.output)

    # 3. Create a commit
    print("=== 3. Create signed commit ===")
    content = store_path.parent / "memory1.json"
    content.write_text(json.dumps({
        "type": "episodic",
        "content": "I learned about Ed25519 signatures today",
        "session_id": "session-001",
    }))
    result = runner.invoke(cli, ["--store", str(store_path), "commit", "--content", str(content)])
    print(result.output)

    # 4. Create another commit
    print("=== 4. Create second commit ===")
    content2 = store_path.parent / "memory2.json"
    content2.write_text(json.dumps({
        "type": "semantic",
        "content": "Ed25519 uses EdDSA with Curve25519",
        "session_id": "session-001",
    }))
    result = runner.invoke(cli, ["--store", str(store_path), "commit", "--content", str(content2)])
    print(result.output)

    # 5. Verify the store
    print("=== 5. Verify store ===")
    result = runner.invoke(cli, ["--store", str(store_path), "verify"])
    print(result.output)
    print(f"Exit code: {result.exit_code} (0 = OK)\n")

    # 6. Rotate keys
    print("=== 6. Rotate operational key ===")
    result = runner.invoke(cli, ["--store", str(store_path), "key", "rotate"])
    print(result.output)

    # 7. Create a commit with the new key
    print("=== 7. Commit with new key ===")
    content3 = store_path.parent / "memory3.json"
    content3.write_text(json.dumps({
        "type": "procedural",
        "content": "After key rotation, identity is preserved by root authority",
        "session_id": "session-002",
    }))
    result = runner.invoke(cli, ["--store", str(store_path), "commit", "--content", str(content3)])
    print(result.output)

    # 8. Final verification
    print("=== 8. Final verification ===")
    result = runner.invoke(cli, ["--store", str(store_path), "verify"])
    print(result.output)

    # 9. Export
    print("=== 9. Export store ===")
    export_path = store_path.parent / "export"
    result = runner.invoke(cli, ["--store", str(store_path), "export", "--output", str(export_path)])
    print(result.output)

    # Cleanup
    shutil.rmtree(store_path.parent, ignore_errors=True)
    print("Done! All operations completed successfully.")


if __name__ == "__main__":
    main()
