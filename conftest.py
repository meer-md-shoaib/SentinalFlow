import sys
from pathlib import Path

# Ensure project root is importable regardless of pytest invocation dir.
ROOT = Path(__file__).resolve().parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))
