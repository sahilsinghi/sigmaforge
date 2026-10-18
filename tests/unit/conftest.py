from __future__ import annotations

import shutil
import sys
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO))

from sigma.collection import SigmaCollection  # noqa: E402

from sigmaforge.events import normalise  # noqa: E402


def make_rule(yaml_text: str):
    return SigmaCollection.from_yaml(yaml_text).rules[0]


def sysmon(event_id: int = 1, **fields):
    raw = {
        "EventID": event_id,
        "Channel": "Microsoft-Windows-Sysmon/Operational",
        "Computer": "WS-1.corp.local",
        "@timestamp": fields.pop("ts", "2026-10-01T10:00:00Z"),
    }
    raw.update(fields)
    return normalise(raw, "test")


def security(event_id: int, **fields):
    raw = {"EventID": event_id, "Channel": "Security", "Computer": "DC-1.corp.local",
           "@timestamp": fields.pop("ts", "2026-10-01T10:00:00Z")}
    raw.update(fields)
    return normalise(raw, "test")


@pytest.fixture(scope="session")
def repo() -> Path:
    return REPO


@pytest.fixture()
def repo_copy(tmp_path: Path) -> Path:
    """A throwaway copy of the rule repository with a small benign corpus."""
    dst = tmp_path / "repo"
    dst.mkdir()
    for name in ("rules", "datasets", "baseline"):
        shutil.copytree(REPO / name, dst / name)
    for name in ("positive", "negative"):
        shutil.copytree(REPO / "tests" / name, dst / "tests" / name)
    for name in ("sigmaforge.yml", "equivalence-exceptions.yml"):
        shutil.copy(REPO / name, dst / name)
    from sigmaforge import baseline

    baseline.generate(dst / "tests" / "benign" / "synthetic", hosts=12, days=14, seed=1337)
    (dst / "baseline" / "metrics.json").unlink(missing_ok=True)
    return dst
