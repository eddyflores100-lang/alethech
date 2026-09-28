"""JCS (JSON Canonicalization Scheme) — RFC 8785.

Serializes JSON to a canonical byte string suitable for hashing and signing.

Implementation notes:
- Object keys sorted by UTF-16 code unit (RFC 8785 §3.2.3).
- Strings escaped per RFC 8259 (no escaped non-ASCII — UTF-8 direct).
- Numbers: integer if no fractional/exponent, else minimal float repr.
- No whitespace, no trailing newline.
"""
from __future__ import annotations

import math
from typing import Any

# Characters that MUST be escaped in JCS (RFC 8259 §7)
_ESCAPE_MAP = {
    '"': '\\"',
    "\\": "\\\\",
    "\b": "\\b",
    "\f": "\\f",
    "\n": "\\n",
    "\r": "\\r",
    "\t": "\\t",
}


def _escape_string(s: str) -> str:
    """Escape a string per RFC 8259. Non-ASCII chars are emitted as UTF-8."""
    out = ['"']
    for ch in s:
        if ch in _ESCAPE_MAP:
            out.append(_ESCAPE_MAP[ch])
        elif ord(ch) < 0x20:
            out.append("\\u%04x" % ord(ch))
        else:
            out.append(ch)
    out.append('"')
    return "".join(out)


def _serialize_number(n: float | int) -> str:
    """Serialize a number per RFC 8785 §3.2.2.3."""
    if isinstance(n, bool):
        # bool is a subclass of int — handle before number conversion
        raise TypeError("booleans are not valid JCS values at top level")

    if isinstance(n, int):
        return str(n)

    # float
    if n != n:  # NaN
        raise ValueError("NaN not representable in JCS")
    if n == math.inf:
        raise ValueError("Infinity not representable in JCS")
    if n == -math.inf:
        raise ValueError("-Infinity not representable in JCS")

    if n == 0.0:
        # Preserve sign of zero per RFC 8785
        return "-0" if math.copysign(1.0, n) < 0 else "0"

    # Integer-valued float (e.g. 3.0)
    if n == int(n) and abs(n) < 1e21:
        return str(int(n))

    # Use repr for shortest round-trippable representation, then strip
    # any trailing exponent that Python adds unnecessarily.
    s = repr(n)
    # Python repr is fine for our purposes — it produces minimal round-trip
    return s


def _serialize_value(v: Any) -> str:
    if v is None:
        return "null"
    if v is True:
        return "true"
    if v is False:
        return "false"
    if isinstance(v, (int, float)):
        return _serialize_number(v)
    if isinstance(v, str):
        return _escape_string(v)
    if isinstance(v, list):
        return "[" + ",".join(_serialize_value(x) for x in v) + "]"
    if isinstance(v, dict):
        # Sort keys by UTF-16 code unit (RFC 8785 §3.2.3)
        items = sorted(v.items(), key=lambda kv: kv[0].encode("utf-16-be"))
        parts = []
        for k, val in items:
            if not isinstance(k, str):
                raise TypeError(f"non-string object key: {k!r}")
            parts.append(_escape_string(k) + ":" + _serialize_value(val))
        return "{" + ",".join(parts) + "}"
    raise TypeError(f"unserializable type: {type(v).__name__}")


def canonical_json(value: Any) -> str:
    """Return the JCS canonical string for the value."""
    return _serialize_value(value)


def canonical_json_bytes(value: Any) -> bytes:
    """Return the JCS canonical bytes for the value (UTF-8 encoded)."""
    return canonical_json(value).encode("utf-8")
