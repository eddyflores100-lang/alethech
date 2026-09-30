"""alethech — verifiable agent continuity protocol.

Reference implementation of the protocol specified in rev 2.
Local-first, zero-LLM, zero-blockchain.
"""
__version__ = "0.9.0"


# Stable embedding API
from .api import Alethech, AlethechError

__all__ = ["Alethech", "AlethechError", "__version__"]
