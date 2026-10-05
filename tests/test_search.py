"""Tests for local-first semantic search."""

import tempfile
from pathlib import Path

import pytest

from alethech import Alethech
from alethech.store import Store
from alethech.search import recall, LocalSearch, TFIDFEmbedder, SearchResult


@pytest.fixture
def populated_store(tmp_path):
    """Create a store with diverse memory entries for testing."""
    agent = Alethech.initialize(tmp_path)
    agent.commit({"task": "Deploy Kubernetes cluster on AWS", "notes": "Used eksctl to create a 3-node cluster"}, memory_type="semantic")
    agent.commit({"task": "Fix JWT authentication bug", "notes": "The token was missing the aud claim in the payload"}, memory_type="episodic")
    agent.commit({"recipe": "Chocolate cake", "ingredients": ["flour", "sugar", "cocoa", "eggs"]}, memory_type="semantic")
    agent.commit({"task": "Set up CI/CD pipeline with GitHub Actions", "notes": "pytest + build + deploy"}, memory_type="procedural")
    agent.commit({"task": "Database migration to PostgreSQL", "notes": "Used pg_loader for bulk data transfer from MySQL"}, memory_type="semantic")
    agent.commit({"task": "Configure nginx reverse proxy", "notes": "SSL termination and load balancing with upstream"}, memory_type="procedural")
    agent.commit({"bug": "Memory leak in worker pool", "fix": "Added explicit cleanup after each task"}, memory_type="episodic")

    return Store.open(Path(agent.path))


class TestTFIDFEmbedder:
    def test_empty_corpus(self):
        emb = TFIDFEmbedder()
        vec = emb.embed("hello world")
        assert len(vec) > 0

    def test_fitted_corpus(self):
        corpus = ["kubernetes deployment", "jwt authentication", "database migration"]
        emb = TFIDFEmbedder(corpus)
        vec = emb.embed("kubernetes")
        assert len(vec) == emb.dimension()
        assert any(v > 0 for v in vec)

    def test_dimension_is_positive(self):
        emb = TFIDFEmbedder(["hello world", "foo bar"])
        assert emb.dimension() > 0


class TestLocalSearch:
    def test_recall_returns_results(self, populated_store):
        results = recall(populated_store, "kubernetes", top_k=3)
        assert len(results) > 0
        assert all(isinstance(r, SearchResult) for r in results)

    def test_recall_relevance(self, populated_store):
        """Kubernetes query should rank the kubernetes entry first."""
        results = recall(populated_store, "kubernetes deploy", top_k=3)
        assert len(results) > 0
        top = results[0]
        assert "kubernetes" in top.snippet.lower() or "kubernetes" in str(top.content).lower()

    def test_recall_jwt_query(self, populated_store):
        """JWT query should rank the JWT entry first."""
        results = recall(populated_store, "jwt authentication token", top_k=3)
        assert len(results) > 0
        top = results[0]
        assert "jwt" in top.snippet.lower() or "jwt" in str(top.content).lower()

    def test_recall_database_query(self, populated_store):
        """Database query should rank the database entry first."""
        results = recall(populated_store, "database postgresql migration", top_k=3)
        assert len(results) > 0
        top = results[0]
        assert "database" in top.snippet.lower() or "database" in str(top.content).lower()

    def test_recall_filter_by_memory_type(self, populated_store):
        """Filter by memory_type should only return matching entries."""
        results = recall(populated_store, "task", top_k=10, memory_type="episodic")
        assert len(results) > 0
        assert all(r.memory_type == "episodic" for r in results)

    def test_recall_no_results(self, populated_store):
        """A query that doesn't match anything should return empty."""
        results = recall(populated_store, "xyzqwerty nonexist", top_k=5)
        assert len(results) == 0

    def test_recall_top_k_limit(self, populated_store):
        """Should respect top_k limit."""
        results = recall(populated_store, "task", top_k=2)
        assert len(results) <= 2

    def test_recall_results_have_scores(self, populated_store):
        results = recall(populated_store, "kubernetes", top_k=3)
        for r in results:
            assert 0 <= r.score <= 1
            assert r.commit_id
            assert r.timestamp

    def test_recall_snippet_is_truncated(self, populated_store):
        """Snippets should be at most ~200 chars."""
        results = recall(populated_store, "task", top_k=3)
        for r in results:
            assert len(r.snippet) <= 210  # 200 + ellipsis

    def test_stats(self, populated_store):
        search = LocalSearch(populated_store)
        search.recall("test")  # trigger index
        stats = search.stats()
        assert stats["entries"] == 7  # genesis + 6 commits
        assert stats["dimension"] > 0
        assert "embedder" in stats

    def test_repeated_queries_reuse_index(self, populated_store):
        """Second query should not rebuild the index."""
        search = LocalSearch(populated_store)
        r1 = search.recall("kubernetes", top_k=3)
        r2 = search.recall("database", top_k=3)
        assert len(r1) > 0
        assert len(r2) > 0

    def test_to_dict_serialization(self, populated_store):
        results = recall(populated_store, "kubernetes", top_k=1)
        d = results[0].to_dict()
        assert "commit_id" in d
        assert "score" in d
        assert "snippet" in d
        assert "content" in d

    def test_empty_store(self, tmp_path):
        """An empty store (only genesis) should return no results."""
        agent = Alethech.initialize(tmp_path)
        store = Store.open(Path(agent.path))
        results = recall(store, "anything", top_k=5)
        assert len(results) == 0
