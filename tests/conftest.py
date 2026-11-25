"""Make the shipped connector core importable from tests."""
import os
import sys

SRC = os.path.join(os.path.dirname(__file__), "..", "connector", "src")
sys.path.insert(0, os.path.abspath(SRC))
