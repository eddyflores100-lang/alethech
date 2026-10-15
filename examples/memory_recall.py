#!/usr/bin/env python3
"""
memory_recall.py — Verbatim reading of the signed memory chain.

Walks the chain from HEAD backwards and prints each commit (agent,
timestamp, type, text). Retrieval is VERBATIM: quote the original content,
never paraphrase. An empty result does NOT prove absence of a fact — only
that it is not indexed here.

Modes:
  (no args)   whole chain
  --last N    the N most recent commits
  --type T    filter by type (semantic | episodic | procedural | memory-vault ...)
  --search S  only commits whose text contains S (case-insensitive)

Configuration:
  ALETHECH_STORE  chain store dir (default ~/.alethech)

© 2026 AliceLabs LLC. MIT License.
"""
import sys, os, json, argparse, glob

STORE = os.environ.get("ALETHECH_STORE",
                       os.path.join(os.path.expanduser("~"), ".alethech"))
HEAD = os.path.join(STORE, "HEAD")


def commits():
    out = []
    for p in glob.glob(os.path.join(STORE, "commits", "*.json")):
        try:
            out.append(json.load(open(p)))
        except Exception:
            continue
    return sorted(out, key=lambda c: c.get("timestamp") or c.get("ts") or "")


def payload_of(c):
    p = c.get("payload") or c.get("content") or {}
    if isinstance(p, str):
        try:
            p = json.loads(p)
        except Exception:
            return p
    return p


def payload_text(c):
    p = payload_of(c)
    return p if isinstance(p, str) else json.dumps(p, ensure_ascii=False)


def main():
    ap = argparse.ArgumentParser(description="Verbatim reader for the alethech chain")
    ap.add_argument("--last", type=int, default=0)
    ap.add_argument("--type", default=None)
    ap.add_argument("--search", default=None)
    args = ap.parse_args()
    cs = commits()
    if args.type:
        cs = [c for c in cs
              if (c.get("type") == args.type)
              or (isinstance(payload_of(c), dict) and payload_of(c).get("type") == args.type)]
    if args.search:
        q = args.search.lower()
        cs = [c for c in cs if q in payload_text(c).lower()]
    if args.last:
        cs = cs[-args.last:]
    print(f"HEAD: {open(HEAD).read().strip() if os.path.exists(HEAD) else '(no HEAD)'}")
    print(f"commits shown: {len(cs)}")
    for c in cs:
        p = payload_of(c)
        t = p.get("type") if isinstance(p, dict) else "?"
        print("-" * 72)
        print(f"hash: {c.get('hash') or c.get('sha256') or '(n/a)'}")
        print(f"agent: {c.get('agent_id') or c.get('author') or '(n/a)'}  "
              f"ts: {c.get('timestamp') or c.get('ts') or '(n/a)'}  type: {t}")
        txt = p.get("text") if isinstance(p, dict) else None
        print(f"text: {txt if txt else payload_text(c)}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
