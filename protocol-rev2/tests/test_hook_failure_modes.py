"""Tests de fallo para confirmar o refutar A1 y E1.

Estos tests NO prueban el comportamiento deseado. Prueban el comportamiento
ACTUAL del hook bajo condiciones de fallo, para clasificar los defectos
de la auditoría adversarial del hook.

A1: ChromaDB pasa, alethech falla → ¿qué queda persistido?
E1: Retry de la misma operación → ¿duplica en ChromaDB?

Después de correr estos tests, sabremos si A1 y E1 son 🔴 confirmados
o 🟡 plausibles-no-confirmados.
"""
import json
import shutil
import tempfile
import uuid
from pathlib import Path
from unittest.mock import patch, MagicMock

import pytest
from click.testing import CliRunner

from alethech.cli import cli
from alethech.integrations.memex.hook import MemexAlethechHook
from alethech.store import Store


class MockMemexStore:
    """Mock memex store that records all writes and can be made to fail/succeed."""
    def __init__(self):
        self.writes = []
        self._fail_on_add = False  # if True, add() raises

    def add(self, text, user_id="agent", metadata=None):
        if self._fail_on_add:
            raise RuntimeError("mock ChromaDB failure")
        memory_id = str(uuid.uuid4())
        self.writes.append({
            "id": memory_id,
            "text": text,
            "user_id": user_id,
            "metadata": metadata or {},
        })
        return {"id": memory_id, "text": text}

    def search(self, query, user_id="agent", limit=5, filters=None):
        return [{"id": w["id"], "text": w["text"], "score": 1.0} for w in self.writes[:limit]]

    def get_all(self, user_id="agent", limit=100000):
        return {"results": self.writes[:limit]}


@pytest.fixture
def tmp_alethech():
    d = tempfile.mkdtemp(prefix="alethech-fail-")
    alethech_path = Path(d) / "alethech"
    runner = CliRunner()
    result = runner.invoke(cli, ["--store", str(alethech_path), "init"])
    assert result.exit_code == 0, result.output
    result = runner.invoke(cli, ["--store", str(alethech_path), "migrate", "--to", "v0.2"])
    assert result.exit_code == 0, result.output
    yield alethech_path
    shutil.rmtree(d, ignore_errors=True)


@pytest.fixture
def runner():
    return CliRunner()


# ============================================================
# Test A1: ChromaDB pasa, alethech falla
# ============================================================

class TestA1_ChromaDBPassesAlethechFails:
    """Reproduce el escenario A1: ChromaDB.write() tiene éxito,
    pero la creación del commit en alethech falla.
    
    Pregunta: ¿qué queda persistido?
    - ¿Memoria en ChromaDB sin commit en alethech? (inconsistencia)
    - ¿Rollback de la memoria en ChromaDB? (atomicidad)
    - ¿Excepción propagada al llamador? (fallo visible)
    """

    def test_A1_chromadb_persists_alethech_fails(self, tmp_alethech):
        """Reproduce: ChromaDB.add() tiene éxito, alethech.commit() falla.
        
        Verifica qué estado queda en cada store después del fallo.
        """
        memex = MockMemexStore()
        hook = MemexAlethechHook(memex_store=memex, alethech_store_path=tmp_alethech)
        assert hook.active, "Hook should be active with v0.2 identity"

        # Patch the internal _sign_memex_write to raise an exception
        with patch.object(hook, '_sign_memex_write', side_effect=RuntimeError("alethech disk full")):
            # Call add() — should propagate the exception
            with pytest.raises(RuntimeError, match="alethech disk full"):
                hook.add("test memory", user_id="agent")

        # Now check what's persisted
        # 1. ChromaDB (mock) state
        chromadb_writes = len(memex.writes)
        print(f"\n[A1] ChromaDB writes after failure: {chromadb_writes}")

        # 2. Alethech state
        store = Store.open(tmp_alethech)
        commits = store.load_commits()
        # Genesis commit always exists (from init/migrate)
        genesis_commits = [c for c in commits.values() if c.content.get("type") == "genesis"]
        memex_commits = [c for c in commits.values() if c.content.get("source") == "memex.write"]
        print(f"[A1] Alethech total commits: {len(commits)}")
        print(f"[A1] Alethech genesis commits: {len(genesis_commits)}")
        print(f"[A1] Alethech memex-write commits: {len(memex_commits)}")
        print(f"[A1] HEAD: {store.read_head()}")

        # Assertions — what actually happens vs what should happen
        if chromadb_writes == 1 and len(memex_commits) == 0:
            # A1 CONFIRMED: ChromaDB has the memory, alethech does NOT have the commit
            print("\n[A1] RESULT: 🔴 CONFIRMED — memory persisted in ChromaDB without corresponding alethech commit")
            print("[A1] This violates the invariant: memory persisted ⇒ corresponding commit exists")
            assert True, "A1 confirmed: inconsistency detected"
        elif chromadb_writes == 0 and len(memex_commits) == 0:
            # A1 REFUTED: ChromaDB rolled back, alethech never created commit
            print("\n[A1] RESULT: ⚪ REFUTED — hook rolled back ChromaDB on alethech failure")
            assert False, "A1 refuted: hook has atomicity (unexpected but good)"
        else:
            print(f"\n[A1] RESULT: unexpected state — ChromaDB={chromadb_writes}, alethech_commits={len(memex_commits)}")

    def test_A1_return_value_on_failure(self, tmp_alethech):
        """When alethech fails, does the caller get a result or an exception?"""
        memex = MockMemexStore()
        hook = MemexAlethechHook(memex_store=memex, alethech_store_path=tmp_alethech)

        with patch.object(hook, '_sign_memex_write', side_effect=RuntimeError("alethech failure")):
            # The exception should propagate
            with pytest.raises(RuntimeError):
                result = hook.add("test")
                # If we reach here, no exception was raised — that's a problem
                print(f"[A1-return] Got result instead of exception: {result}")

        print("[A1-return] Exception was propagated correctly")


# ============================================================
# Test E1: Retry duplica memorias
# ============================================================

class TestE1_RetryDuplicatesMemories:
    """Reproduce el escenario E1: primer intento falla en alethech,
    el llamador reintenta con el mismo texto. ¿Se duplica en ChromaDB?
    
    Pregunta: después del retry exitoso, ¿cuántas memorias hay en ChromaDB?
    """

    def test_E1_retry_with_same_text(self, tmp_alethech):
        """First attempt: ChromaDB succeeds, alethech fails.
        Second attempt (retry): both succeed.
        
        ¿Cuántas memorias quedan en ChromaDB?
        """
        memex = MockMemexStore()
        hook = MemexAlethechHook(memex_store=memex, alethech_store_path=tmp_alethech)
        assert hook.active

        text = "memory to retry"
        user_id = "agent"

        # Attempt 1: alethech fails
        call_count = [0]
        original_sign = hook._sign_memex_write

        def fail_on_first_success_on_second(*args, **kwargs):
            call_count[0] += 1
            if call_count[0] == 1:
                raise RuntimeError("alethech transient failure")
            # Second call succeeds
            return original_sign(*args, **kwargs)

        with patch.object(hook, '_sign_memex_write', side_effect=fail_on_first_success_on_second):
            # Attempt 1 — should raise
            with pytest.raises(RuntimeError, match="alethech transient failure"):
                hook.add(text, user_id=user_id)

            # Attempt 2 (retry) — should succeed
            result = hook.add(text, user_id=user_id)

        # Now check state
        chromadb_writes = len(memex.writes)
        chromadb_texts = [w["text"] for w in memex.writes]
        chromadb_ids = [w["id"] for w in memex.writes]

        store = Store.open(tmp_alethech)
        commits = store.load_commits()
        memex_commits = [c for c in commits.values() if c.content.get("source") == "memex.write"]

        print(f"\n[E1] ChromaDB writes: {chromadb_writes}")
        print(f"[E1] ChromaDB texts: {chromadb_texts}")
        print(f"[E1] ChromaDB ids: {chromadb_ids}")
        print(f"[E1] Alethech memex-write commits: {len(memex_commits)}")

        if chromadb_writes == 2 and len(memex_commits) == 1:
            print("\n[E1] RESULT: 🔴 CONFIRMED — retry created duplicate memory in ChromaDB")
            print("[E1] ChromaDB has 2 memories (same text), alethech has 1 commit (from retry)")
            assert True, "E1 confirmed: duplicate detected"
        elif chromadb_writes == 1 and len(memex_commits) == 1:
            print("\n[E1] RESULT: ⚪ REFUTED — ChromaDB deduplicated or hook prevented duplicate")
            assert False, "E1 refuted: no duplication (unexpected)"
        elif chromadb_writes == 2 and len(memex_commits) == 2:
            print("\n[E1] RESULT: 🔴 CONFIRMED (worse) — both ChromaDB and alethech have duplicates")
            assert True, "E1 confirmed with double duplication"
        else:
            print(f"\n[E1] RESULT: unexpected — ChromaDB={chromadb_writes}, alethech={len(memex_commits)}")

    def test_E1_retry_with_idempotency_check(self, tmp_alethech):
        """If the hook had idempotency_key support, would the retry be safe?
        
        This test documents what the CORRECT behavior would look like,
        even though the hook doesn't support it yet.
        """
        # This is a documentation test — it should FAIL (assertion error)
        # because the hook doesn't support idempotency_key yet.
        memex = MockMemexStore()
        hook = MemexAlethechHook(memex_store=memex, alethech_store_path=tmp_alethech)

        # Try to pass idempotency_key — should get TypeError (not supported)
        with pytest.raises(TypeError):
            hook.add("test", idempotency_key="key-123")

        print("\n[E1-idempotency] Hook does NOT support idempotency_key parameter (as expected)")
        print("[E1-idempotency] To fix E1, hook needs idempotency_key support")


# ============================================================
# Test B1: orden de escritura
# ============================================================

class TestB1_WriteOrder:
    """Documenta el orden actual de escritura: ChromaDB primero, alethech después.
    
    Esto es información para clasificar B1, no un test de pass/fail.
    """

    def test_B1_chromadb_called_before_alethech(self, tmp_alethech):
        """Verify that ChromaDB.add() is called BEFORE _sign_memex_write()."""
        memex = MockMemexStore()
        hook = MemexAlethechHook(memex_store=memex, alethech_store_path=tmp_alethech)

        call_order = []

        original_memex_add = memex.add
        def tracking_memex_add(*args, **kwargs):
            call_order.append("chromadb.add")
            return original_memex_add(*args, **kwargs)

        original_sign = hook._sign_memex_write
        def tracking_sign(*args, **kwargs):
            call_order.append("alethech.sign")
            return original_sign(*args, **kwargs)

        memex.add = tracking_memex_add
        hook._sign_memex_write = tracking_sign

        hook.add("test order")

        print(f"\n[B1] Call order: {call_order}")
        assert call_order == ["chromadb.add", "alethech.sign"], \
            f"Expected ChromaDB first, alethech second. Got: {call_order}"
        print("[B1] Confirmed: ChromaDB.add() is called BEFORE alethech._sign_memex_write()")
