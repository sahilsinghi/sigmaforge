"""MITRE ATT&CK Enterprise data used for tag checks and coverage maps.

A snapshot (``data/attack-enterprise.json``) is shipped so coverage reports
are reproducible offline. ``sigmaforge attack refresh`` rebuilds it from the
same MITRE STIX feed pySigma's tag validator uses. ATT&CK v19 renamed
Defense Evasion to *Stealth*, added *Defense Impairment* (TA0112) and moved
log-clearing to T1685.005; rules tagged against older releases fail lint.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path

SNAPSHOT = Path(__file__).parent / "data" / "attack-enterprise.json"


@dataclass(frozen=True)
class Attack:
    version: str
    tactics: list[tuple[str, str]]  # (TA id, shortname) in matrix order
    techniques: dict[str, dict]  # T-id -> {name, tactics}

    def tactic_shortnames(self) -> list[str]:
        return [short for _, short in self.tactics]

    def tactic_id(self, shortname: str) -> str | None:
        for tid, short in self.tactics:
            if short == shortname:
                return tid
        return None

    def name(self, technique: str) -> str:
        info = self.techniques.get(technique.upper())
        return info["name"] if info else technique

    def tactics_of(self, technique: str) -> list[str]:
        info = self.techniques.get(technique.upper())
        return list(info["tactics"]) if info else []

    def parent(self, technique: str) -> str:
        return technique.split(".", 1)[0]

    def exists(self, technique: str) -> bool:
        return technique.upper() in self.techniques


@lru_cache(maxsize=1)
def load(path: Path = SNAPSHOT) -> Attack:
    data = json.loads(path.read_text(encoding="utf-8"))
    return Attack(
        version=str(data["version"]),
        tactics=[(t["id"], t["shortname"]) for t in data["tactics"]],
        techniques=data["techniques"],
    )


def refresh(path: Path = SNAPSHOT) -> Attack:
    """Rebuild the snapshot from MITRE's STIX feed (via pySigma; needs network)."""
    import sigma.data.mitre_attack as mitre

    order = [
        "TA0043", "TA0042", "TA0001", "TA0002", "TA0003", "TA0004", "TA0005",
        "TA0112", "TA0006", "TA0007", "TA0008", "TA0009", "TA0011", "TA0010", "TA0040",
    ]
    tactics = mitre.mitre_attack_tactics
    order += [t for t in sorted(tactics) if t not in order]
    names = mitre.mitre_attack_techniques
    mapping = mitre.mitre_attack_techniques_tactics_mapping
    snap = {
        "source": mitre.MITRE_ATTACK_ENTERPRISE_URL,
        "version": mitre.mitre_attack_version,
        "tactics": [{"id": tid, "shortname": tactics[tid]} for tid in order if tid in tactics],
        "techniques": {k: {"name": names[k], "tactics": mapping.get(k, [])} for k in sorted(names) if k.startswith("T")},
    }
    path.write_text(json.dumps(snap, indent=0, sort_keys=True), encoding="utf-8")
    load.cache_clear()
    return load(path)
