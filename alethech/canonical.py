"""JCS (JSON Canonicalization Scheme) — RFC 8785 (with errata).

Serializes JSON to a canonical byte string suitable for hashing and signing.

Implementation notes:
- Object keys sorted by UTF-16 code unit (RFC 8785 §3.2.3).
- Strings escaped per RFC 8259 (no escaped non-ASCII — UTF-8 direct).
- Numbers: serialized per ECMAScript Number::toString() algorithm.
  - Integer if no fractional/exponent, else minimal float repr.
  - -0 serializes as "0" (RFC 8785 erratum: sign of zero NOT preserved).
  - Positive exponents keep the '+' sign (e.g. "1e+21", not "1e21").
  - Negative exponents strip leading zeros (e.g. "1e-7", not "1e-07").
  - Decimal notation for 1e-6 <= |n| < 1e21, scientific otherwise.
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
    """Serialize a number per RFC 8785 §3.2.2.3.

    Uses Python's repr() for the shortest round-trip representation,
    then fixes the divergences between Python's float repr and
    ECMAScript Number.prototype.toString() (which is what JCS requires):

    1. Python repr(1e+21) = '1e+21' → JCS wants '1e21' (no '+')
    2. Python repr(1e-07) = '1e-07' → JCS wants '1e-7' (no leading zero)
    3. Python repr(1.2345678901234568e+20) = '1.2345678901234568e+20' →
       JCS wants '123456789012345680000' (decimal notation for |n| < 1e21)
    4. Python repr(3.0) = '3.0' → JCS wants '3' (strip '.0' for integers)
    5. Python repr(1.5e-05) = '1.5e-05' → JCS wants '0.000015' (decimal
       for |n| >= 1e-6, even when Python uses scientific)
    """
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
        # RFC 8785 erratum + ECMAScript Number::toString(x): both +0 and -0
        # serialize as "0". The sign of zero is NOT preserved.
        # Reference: ECMAScript spec §6.1.6.1.20 step 2:
        #   "If x is +0 or -0, return the String value '0'."
        # Reference: RFC 8785 Appendix A test vectors:
        #   0x0000000000000000 → "0"
        #   0x8000000000000000 → "0"  (negative zero)
        return "0"

    abs_n = abs(n)

    # Python's repr gives the shortest round-trip representation
    s = repr(n)

    # Handle scientific notation
    if 'e' in s or 'E' in s:
        s_lower = s.lower()
        e_pos = s_lower.index('e')
        mantissa = s[:e_pos]
        exp = int(s[e_pos + 1:])

        # ECMAScript uses scientific notation for |n| >= 1e21 or |n| < 1e-6
        # Otherwise, it uses decimal notation
        if abs_n >= 1e21 or abs_n < 1e-6:
            # Keep scientific notation, but fix the format:
            # - KEEP '+' for positive exponents (RFC 8785 / ECMAScript
            #   requires '1e+21', not '1e21'). Reference: ECMAScript
            #   Number::toString spec, and cyberphone reference impl.
            # - Strip leading zeros from negative exponents:
            #   Python repr(1e-7) = '1e-07', JCS wants '1e-7'.
            # Using '{:+d}' format gives '+21' for positive and '-7' for negative
            # (without leading zeros), which is exactly the ECMAScript format.
            return f"{mantissa}e{exp:+d}"
        else:
            # Convert from scientific to decimal notation
            return _scientific_to_decimal(mantissa, exp)

    # Decimal notation from repr — strip trailing '.0' for integer-valued floats
    if s.endswith('.0'):
        return s[:-2]

    return s


def _scientific_to_decimal(mantissa: str, exp: int) -> str:
    """Convert a float from scientific notation (mantissa × 10^exp) to
    decimal notation, matching ECMAScript Number.prototype.toString().

    Examples:
      _scientific_to_decimal('1.2345678901234568', 20) → '123456789012345680000'
      _scientific_to_decimal('1.5', -5) → '0.000015'
      _scientific_to_decimal('1', 20) → '100000000000000000000'
    """
    negative = mantissa.startswith('-')
    if negative:
        mantissa = mantissa[1:]

    if '.' in mantissa:
        int_part, frac_part = mantissa.split('.')
    else:
        int_part, frac_part = mantissa, ''

    # All digits of the number, without the decimal point
    digits = int_part + frac_part
    # Where the decimal point should go (relative to start of digits)
    decimal_pos = len(int_part) + exp

    if decimal_pos <= 0:
        # Need leading zeros: 0.000...digits
        result = '0.' + '0' * (-decimal_pos) + digits
    elif decimal_pos >= len(digits):
        # Need trailing zeros: digits000...
        result = digits + '0' * (decimal_pos - len(digits))
    else:
        # Decimal point in the middle
        result = digits[:decimal_pos] + '.' + digits[decimal_pos:]

    if negative:
        result = '-' + result

    return result


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
