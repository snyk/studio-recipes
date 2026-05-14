"""Test helper utilities."""

import json


def read_json(path):
    """Load JSON from a file path."""
    with open(path) as f:
        return json.load(f)
