"""Local-first semantic search over verified memory.

Provides recall-by-meaning without any server. Uses TF-IDF over the
verified memory entries to rank by relevance. This is intentionally
lightweight: no neural network, no GPU, no 500MB model download.

The search works as follows:
1. Collect all verified memory entries (the same VerifiedMemoryView
   that the chat adapter uses).
2. Build a TF-IDF index over the content of each entry.
3. When the user queries, compute TF-IDF of the query and rank
   entries by cosine similarity.
4. Return the top-k entries, sorted by relevance.

This gives "find memories about X" without any external dependency.
For production-grade semantic search, the caller can optionally
plug in sentence-transformers by providing a custom embedder.

Usage:
    from alethech.search import LocalSearch, recall

    # Simple recall — returns top 5 entries matching the query
    results = recall(store, "how to deploy kubernetes", top_k=5)

    # Advanced — with custom embedder
    from alethech.search import LocalSearch, TFIDFEmbedder
    search = LocalSearch(store, embedder=TFIDFEmbedder())
    results = search.recall("kubernetes deployment", top_k=10)
"""

from __future__ import annotations

import math
import re
from collections import Counter
from dataclasses import dataclass, field
from typing import Any, Protocol

from .adapters import VerifiedMemoryView, build_memory_view
from .store import Store


# ------------------------------------------------------------------
# Types
# ------------------------------------------------------------------


@dataclass(frozen=True)
class SearchResult:
    """A single recall result."""

    commit_id: str
    agent_id: str
    memory_type: str
    content: dict[str, Any]
    timestamp: str
    score: float
    snippet: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "commit_id": self.commit_id,
            "agent_id": self.agent_id,
            "memory_type": self.memory_type,
            "content": self.content,
            "timestamp": self.timestamp,
            "score": round(self.score, 4),
            "snippet": self.snippet,
        }


class Embedder(Protocol):
    """Interface for text embedding strategies."""

    def embed(self, text: str) -> list[float]:
        """Return a vector representation of *text*."""
        ...

    def dimension(self) -> int:
        """Return the dimension of the embedding vectors."""
        ...


# ------------------------------------------------------------------
# TF-IDF embedder — zero dependencies, fast, local
# ------------------------------------------------------------------


_WORD_RE = re.compile(r"[a-z0-9áéíóúñü]+", re.IGNORECASE)
_STOPWORDS = frozenset(
    """a an the and or but not no yes is are was were be been being have has had
    do does did will would could should may might can must shall to of in on
    at by for with from into out up down over under again further then once
    here there all any both each few more most other some such only own same
    so than too very s t can just don should now i me my we our you your he
    him his she her it its they them their what which who whom this that
    these those am is are was were be been being have has had do does did
    will would shall should may might must can need dare ought to
    about above after again against all am an and any are aren as at be
    because been before being below between both but by can cannot could
    did do does doing don down during each few for from further had has
    have having he her here hers herself him himself his how i if in into
    is it its itself just me more most my myself no nor not now of off on
    once only or other our ours ourselves out over own same she should so
    some such t than that the their theirs them themselves then there
    these they this those through to too under until up very was we were
    what when where which while who whom why with you your yours yourself
    yourselves el la los las de del en con por para como mas pero o y que
    se su sus es un una unos unas lo al le les si no ya muy tambien
    """.split()
)


def _tokenize(text: str) -> list[str]:
    """Extract lowercase word tokens, filtering stopwords and short words."""
    tokens = _WORD_RE.findall(text.lower())
    return [t for t in tokens if len(t) >= 2 and t not in _STOPWORDS]


class TFIDFEmbedder:
    """TF-IDF embedder with a shared vocabulary.

    Unlike neural embedders, TF-IDF requires a corpus to compute IDF
    weights. The embedder is initialized with a corpus, then can embed
    individual texts using the learned IDF.

    This is intentionally simple. For production-grade semantic search,
    plug in sentence-transformers via a custom Embedder that delegates
    to SentenceTransformer.encode().
    """

    def __init__(self, corpus: list[str] | None = None) -> None:
        self._idf: dict[str, float] = {}
        self._vocab: dict[str, int] = {}
        if corpus:
            self._fit(corpus)

    def _fit(self, corpus: list[str]) -> None:
        """Compute IDF weights from *corpus*."""
        n_docs = len(corpus)
        if n_docs == 0:
            return

        doc_freq: Counter[str] = Counter()
        for doc in corpus:
            tokens = set(_tokenize(doc))
            for token in tokens:
                doc_freq[token] += 1

        for token, freq in doc_freq.items():
            self._idf[token] = math.log((n_docs + 1) / (freq + 1)) + 1

        self._vocab = {token: i for i, token in enumerate(sorted(self._idf.keys()))}

    def dimension(self) -> int:
        return max(len(self._vocab), 1)

    def embed(self, text: str) -> list[float]:
        """Embed *text* as a TF-IDF vector."""
        if not self._vocab:
            # No corpus fitted yet — fall back to raw TF
            tokens = _tokenize(text)
            counts = Counter(tokens)
            total = sum(counts.values()) or 1
            return [counts[t] / total for t in sorted(counts.keys())]

        tokens = _tokenize(text)
        counts = Counter(tokens)
        total = sum(counts.values()) or 1

        vec = [0.0] * len(self._vocab)
        for token, count in counts.items():
            if token in self._vocab:
                tf = count / total
                idf = self._idf.get(token, 1.0)
                vec[self._vocab[token]] = tf * idf

        return vec


def _cosine_similarity(a: list[float], b: list[float]) -> float:
    """Compute cosine similarity between two vectors."""
    if not a or not b:
        return 0.0
    # Pad shorter vector with zeros
    max_len = max(len(a), len(b))
    a_padded = a + [0.0] * (max_len - len(a))
    b_padded = b + [0.0] * (max_len - len(b))

    dot = sum(x * y for x, y in zip(a_padded, b_padded))
    norm_a = math.sqrt(sum(x * x for x in a_padded))
    norm_b = math.sqrt(sum(x * x for x in b_padded))

    if norm_a == 0 or norm_b == 0:
        return 0.0

    return dot / (norm_a * norm_b)


def _entry_to_text(entry: Any) -> str:
    """Flatten a memory entry's content into searchable text."""
    parts: list[str] = []

    # Content can be any dict — flatten values to strings
    content = getattr(entry, "content", None) or {}
    if isinstance(content, dict):
        for value in content.values():
            if isinstance(value, str):
                parts.append(value)
            elif isinstance(value, (int, float, bool)):
                parts.append(str(value))
            elif isinstance(value, (list, dict)):
                parts.append(json.dumps(value, ensure_ascii=False))

    # Also include memory_type and any text fields
    mem_type = getattr(entry, "memory_type", "")
    if mem_type:
        parts.append(mem_type)

    return " ".join(parts)


import json  # needed for _entry_to_text


def _make_snippet(text: str, max_len: int = 200) -> str:
    """Create a preview snippet from text."""
    text = text.strip()
    if len(text) <= max_len:
        return text
    return text[:max_len].rsplit(" ", 1)[0] + "…"


# ------------------------------------------------------------------
# LocalSearch — the main search engine
# ------------------------------------------------------------------


class LocalSearch:
    """Local-first semantic search over verified memory.

    Usage:
        search = LocalSearch(store)
        results = search.recall("kubernetes deployment", top_k=5)

    The search engine:
    1. Verifies the store (no results from unverified history).
    2. Builds a TF-IDF index over all memory entries.
    3. Ranks entries by cosine similarity to the query.

    No server, no GPU, no model download. For neural embeddings,
    pass a custom embedder:
        search = LocalSearch(store, embedder=my_sentence_transformer)
    """

    def __init__(self, store: Store, embedder: Embedder | None = None) -> None:
        self._store = store
        self._view: VerifiedMemoryView | None = None
        self._embedder: Embedder | None = embedder
        self._entry_vectors: list[list[float]] = []
        self._entries: list[Any] = []

    def _ensure_index(self) -> VerifiedMemoryView:
        """Build the search index if not already built."""
        if self._view is not None:
            return self._view

        self._view = build_memory_view(self._store)
        self._entries = list(self._view.entries)

        if not self._entries:
            return self._view

        # Build corpus for TF-IDF
        corpus = [_entry_to_text(e) for e in self._entries]

        # If no embedder provided, use TF-IDF
        if self._embedder is None:
            self._embedder = TFIDFEmbedder(corpus)
        else:
            # If a custom embedder is provided, we still need to fit it
            # if it's a TFIDFEmbedder. Neural embedders don't need fitting.
            if isinstance(self._embedder, TFIDFEmbedder):
                self._embedder._fit(corpus)

        # Embed all entries
        self._entry_vectors = [self._embedder.embed(text) for text in corpus]

        return self._view

    def recall(
        self,
        query: str,
        *,
        top_k: int = 5,
        memory_type: str | None = None,
        min_score: float = 0.01,
    ) -> list[SearchResult]:
        """Find the top-k memory entries matching *query*.

        Parameters:
            query: Natural language search query.
            top_k: Maximum number of results to return.
            memory_type: Filter by memory type (semantic/episodic/procedural).
            min_score: Minimum similarity score (0-1). Results below this
                are excluded.

        Returns:
            List of SearchResult, sorted by relevance (highest first).
        """
        view = self._ensure_index()

        if not self._entries:
            return []

        query_vec = self._embedder.embed(query)

        scored: list[tuple[float, int]] = []
        for i, entry_vec in enumerate(self._entry_vectors):
            entry = self._entries[i]

            # Filter by memory type if requested
            if memory_type and entry.memory_type != memory_type:
                continue

            score = _cosine_similarity(query_vec, entry_vec)
            if score >= min_score:
                scored.append((score, i))

        # Sort by score descending
        scored.sort(key=lambda x: -x[0])

        # Take top_k
        results: list[SearchResult] = []
        for score, idx in scored[:top_k]:
            entry = self._entries[idx]
            text = _entry_to_text(entry)
            results.append(
                SearchResult(
                    commit_id=entry.commit_id,
                    agent_id=entry.agent_id,
                    memory_type=entry.memory_type,
                    content=entry.content,
                    timestamp=entry.timestamp,
                    score=score,
                    snippet=_make_snippet(text),
                )
            )

        return results

    def stats(self) -> dict[str, Any]:
        """Return search index statistics."""
        view = self._ensure_index()
        return {
            "entries": len(self._entries),
            "embedder": type(self._embedder).__name__ if self._embedder else "none",
            "dimension": self._embedder.dimension() if self._embedder else 0,
            "head": view.head,
        }


# ------------------------------------------------------------------
# Convenience function
# ------------------------------------------------------------------


def recall(
    store: Store,
    query: str,
    *,
    top_k: int = 5,
    memory_type: str | None = None,
) -> list[SearchResult]:
    """Search verified memory for entries matching *query*.

    This is the simplest API — creates a LocalSearch, runs the query,
    and returns results. For repeated queries, create a LocalSearch
    instance once and call .recall() multiple times.

    Example:
        from alethech.search import recall
        results = recall(store, "how to deploy kubernetes", top_k=3)
        for r in results:
            print(f"{r.score:.2f} {r.commit_id[:16]} {r.snippet}")
    """
    search = LocalSearch(store)
    return search.recall(query, top_k=top_k, memory_type=memory_type)
