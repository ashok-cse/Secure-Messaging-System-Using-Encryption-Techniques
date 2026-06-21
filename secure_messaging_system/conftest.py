"""
conftest.py
-----------
Makes the project's top-level modules (auth, database, crypto_utils, ...)
importable from the tests/ directory by adding this folder to sys.path.
This lets `pytest` be run from the project root without any extra setup.
"""

import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))
