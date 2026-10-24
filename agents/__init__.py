"""SentinelFlow Multi-Agent System Package."""

import sys
import asyncio

# Ensure UTF-8 output on Windows consoles to prevent charmap/cp1252 encoding crashes
if sys.stdout and hasattr(sys.stdout, "reconfigure"):
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass
if sys.stderr and hasattr(sys.stderr, "reconfigure"):
    try:
        sys.stderr.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

# Ensure an active asyncio event loop exists on MainThread for Python 3.12+ compatibility
try:
    asyncio.get_event_loop()
except RuntimeError:
    _loop = asyncio.new_event_loop()
    asyncio.set_event_loop(_loop)
