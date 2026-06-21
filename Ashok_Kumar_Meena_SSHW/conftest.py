"""
conftest.py
-----------
Adds the source_code/ folder to sys.path so the tests in tests/ can import the
application modules (auth, database, crypto_utils, ...) when pytest is run from
the project root.
"""

import sys
from pathlib import Path

SOURCE_DIR = Path(__file__).resolve().parent / "source_code"
if str(SOURCE_DIR) not in sys.path:
    sys.path.insert(0, str(SOURCE_DIR))
