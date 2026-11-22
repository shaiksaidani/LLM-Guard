"""
Pytest configuration and environment fixtures for LLM-Guard DLP testing.
"""

import sys
import os

# Ensure project root is always accessible to pytest runs
ROOT_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if ROOT_DIR not in sys.path:
    sys.path.insert(0, ROOT_DIR)
