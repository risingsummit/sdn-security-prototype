from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from .models import SecurityPolicy, load_inventory, load_policy, validate_policy


def read_json(path: str | Path) -> dict[str, Any]:
    config_path = Path(path)
    with config_path.open("r", encoding="utf-8") as handle:
        return json.load(handle)


def load_inventory_file(path: str | Path):
    return load_inventory(read_json(path))


def load_policy_file(path: str | Path) -> SecurityPolicy:
    policy = load_policy(read_json(path))
    validate_policy(policy)
    return policy
