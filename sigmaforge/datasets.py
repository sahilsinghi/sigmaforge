"""Fetch public attack telemetry from a pinned commit, verified file by file.

Large third-party datasets stay out of Git history. Instead the repository
pins a commit and records each file's Git blob SHA-1 in a lock file
(``datasets/<name>.lock.json``). ``fetch`` downloads only what the rules
reference (or everything with ``--all``) into ``.cache/datasets`` and refuses
any file whose content does not hash to the pinned blob ID, so CI replays
exactly the bytes that were reviewed.
"""

from __future__ import annotations

import hashlib
import json
import urllib.parse
import urllib.request
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable

USER_AGENT = "sigmaforge-dataset-fetch/0.1"


@dataclass(frozen=True)
class Dataset:
    name: str
    repo: str  # owner/name on GitHub
    commit: str
    license: str


DATASETS = {
    "evtx-attack-samples": Dataset(
        name="evtx-attack-samples",
        repo="sbousseaden/EVTX-ATTACK-SAMPLES",
        commit="4ceed2f4706daf601c212a8f91c113dd85349a2c",
        license="GPL-3.0 (not redistributed here; fetched at test time)",
    ),
}


class DatasetError(Exception):
    pass


def git_blob_sha1(data: bytes) -> str:
    header = f"blob {len(data)}\0".encode()
    return hashlib.sha1(header + data).hexdigest()


def cache_dir(root: Path, ds: Dataset) -> Path:
    return root / ".cache" / "datasets" / ds.name / ds.commit[:12]


def lock_path(root: Path, ds: Dataset) -> Path:
    return root / "datasets" / f"{ds.name}.lock.json"


def _get(url: str, timeout: int = 60) -> bytes:
    req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
    with urllib.request.urlopen(req, timeout=timeout) as resp:  # noqa: S310 - fixed https hosts
        return resp.read()


def build_lock(root: Path, ds: Dataset) -> dict:
    """Record every file in the pinned tree with its blob SHA (needs network)."""
    url = f"https://api.github.com/repos/{ds.repo}/git/trees/{ds.commit}?recursive=1"
    tree = json.loads(_get(url))
    files = {
        item["path"]: {"sha": item["sha"], "size": item.get("size", 0)}
        for item in tree.get("tree", [])
        if item.get("type") == "blob" and item["path"].lower().endswith(".evtx")
    }
    lock = {"dataset": ds.name, "repo": ds.repo, "commit": ds.commit, "license": ds.license, "files": files}
    path = lock_path(root, ds)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(lock, indent=1, sort_keys=True) + "\n", encoding="utf-8")
    return lock


def load_lock(root: Path, ds: Dataset) -> dict:
    path = lock_path(root, ds)
    if not path.exists():
        raise DatasetError(f"no lock file for {ds.name}; run `sigmaforge datasets lock {ds.name}`")
    lock = json.loads(path.read_text(encoding="utf-8"))
    if lock.get("commit") != ds.commit:
        raise DatasetError(f"{path} pins {lock.get('commit')} but the code pins {ds.commit}")
    return lock


def local_path(root: Path, dataset: str, rel: str) -> Path:
    ds = DATASETS.get(dataset)
    if ds is None:
        raise DatasetError(f"unknown dataset {dataset!r}")
    return cache_dir(root, ds) / rel


def fetch(root: Path, dataset: str, paths: Iterable[str] | None = None) -> list[Path]:
    """Download (and verify) files. ``paths=None`` fetches the whole dataset."""
    ds = DATASETS.get(dataset)
    if ds is None:
        raise DatasetError(f"unknown dataset {dataset!r}")
    lock = load_lock(root, ds)
    wanted = sorted(set(paths)) if paths is not None else sorted(lock["files"])
    out: list[Path] = []
    for rel in wanted:
        entry = lock["files"].get(rel)
        if entry is None:
            raise DatasetError(f"{rel} is not in the pinned {ds.name} tree")
        dest = cache_dir(root, ds) / rel
        if dest.exists() and git_blob_sha1(dest.read_bytes()) == entry["sha"]:
            out.append(dest)
            continue
        quoted = urllib.parse.quote(rel)
        data = _get(f"https://raw.githubusercontent.com/{ds.repo}/{ds.commit}/{quoted}")
        actual = git_blob_sha1(data)
        if actual != entry["sha"]:
            raise DatasetError(f"{rel}: blob {actual} does not match pinned {entry['sha']}")
        dest.parent.mkdir(parents=True, exist_ok=True)
        dest.write_bytes(data)
        out.append(dest)
    return out


def available(root: Path, dataset: str, rel: str) -> bool:
    try:
        return local_path(root, dataset, rel).exists()
    except DatasetError:
        return False
