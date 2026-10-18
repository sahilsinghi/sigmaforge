"""Load telemetry from disk and normalise it into one canonical shape.

Supported inputs
----------------
* ``.jsonl`` / ``.ndjson``  - one event per line (optionally ``.gz``)
* ``.json``                 - a single event or a JSON array of events
* ``.evtx``                 - Windows event logs, parsed with python-evtx

Supported schemas
-----------------
* Flat Windows / Sysmon ``EventData`` field names (``Image``, ``CommandLine``)
  - this is the canonical form and what the rules are written against.
* Elastic Common Schema / Winlogbeat documents (``process.executable`` or
  nested ``{"process": {"executable": ...}}``), mapped back to canonical.
* Windows Security 4688 process creation, aliased onto Sysmon names.

Every event must carry a channel, an event ID, a host name and a timestamp.
Timestamps are always taken from the event itself; nothing in SigmaForge
compares them with the current clock, so years-old telemetry replays the
same way as fresh telemetry.
"""

from __future__ import annotations

import gzip
import io
import json
import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable, Iterator

from sigmaforge.logsource import SECURITY, EventSource, classify

META_KEYS = ("EventID", "Channel", "Computer", "@timestamp")


@dataclass
class Event:
    fields: dict[str, Any]
    channel: str
    event_id: int
    computer: str
    timestamp: datetime
    source: EventSource
    origin: str = ""
    _lower_keys: dict[str, str] | None = field(default=None, repr=False)

    def get(self, name: str) -> Any:
        """Field lookup: exact name first, then case-insensitive."""
        if name in self.fields:
            return self.fields[name]
        if self._lower_keys is None:
            self._lower_keys = {k.lower(): k for k in self.fields}
        real = self._lower_keys.get(name.lower())
        return self.fields.get(real) if real is not None else None

    def has(self, name: str) -> bool:
        if name in self.fields:
            return True
        if self._lower_keys is None:
            self._lower_keys = {k.lower(): k for k in self.fields}
        return name.lower() in self._lower_keys

    @property
    def epoch(self) -> float:
        return self.timestamp.timestamp()


class EventFormatError(ValueError):
    pass


# --------------------------------------------------------------------------
# Timestamps
# --------------------------------------------------------------------------

_FRACTION = re.compile(r"(\.\d{6})\d+")


def parse_timestamp(value: Any) -> datetime:
    if isinstance(value, datetime):
        return value if value.tzinfo else value.replace(tzinfo=timezone.utc)
    if isinstance(value, (int, float)):
        # epoch seconds or milliseconds
        seconds = value / 1000.0 if value > 1e11 else float(value)
        return datetime.fromtimestamp(seconds, tz=timezone.utc)
    if not isinstance(value, str) or not value.strip():
        raise EventFormatError(f"unparseable timestamp: {value!r}")
    text = value.strip().replace(" ", "T", 1)
    text = _FRACTION.sub(r"\1", text)  # EVTX uses 7 fractional digits
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"
    try:
        ts = datetime.fromisoformat(text)
    except ValueError as exc:
        raise EventFormatError(f"unparseable timestamp: {value!r}") from exc
    return ts if ts.tzinfo else ts.replace(tzinfo=timezone.utc)


# --------------------------------------------------------------------------
# Schema normalisation
# --------------------------------------------------------------------------

# ECS / Winlogbeat field -> canonical Sysmon / Windows field
ECS_TO_CANONICAL = {
    "process.executable": "Image",
    "process.command_line": "CommandLine",
    "process.parent.executable": "ParentImage",
    "process.parent.command_line": "ParentCommandLine",
    "process.pe.original_file_name": "OriginalFileName",
    "process.working_directory": "CurrentDirectory",
    "process.pid": "ProcessId",
    "process.parent.pid": "ParentProcessId",
    "registry.path": "TargetObject",
    "file.path": "TargetFilename",
    "destination.ip": "DestinationIp",
    "destination.port": "DestinationPort",
    "destination.domain": "DestinationHostname",
    "source.ip": "SourceIp",
    "source.port": "SourcePort",
    "dns.question.name": "QueryName",
    "user.name": "User",
}


def _flatten(doc: dict[str, Any], prefix: str = "") -> dict[str, Any]:
    out: dict[str, Any] = {}
    for key, value in doc.items():
        name = f"{prefix}{key}"
        if isinstance(value, dict):
            out.update(_flatten(value, name + "."))
        else:
            out[name] = value
    return out


def _from_ecs(flat: dict[str, Any]) -> dict[str, Any]:
    fields: dict[str, Any] = {}
    for key, value in flat.items():
        if key.startswith("winlog.event_data."):
            fields[key[len("winlog.event_data."):]] = value
    for ecs, canon in ECS_TO_CANONICAL.items():
        if ecs in flat and canon not in fields:
            fields[canon] = flat[ecs]
    fields["EventID"] = flat.get("event.code") or flat.get("winlog.event_id")
    fields["Channel"] = flat.get("winlog.channel") or flat.get("event.provider")
    fields["Computer"] = flat.get("host.name") or flat.get("winlog.computer_name")
    fields["@timestamp"] = flat.get("@timestamp")
    return fields


def _is_ecs(doc: dict[str, Any]) -> bool:
    if any(k in doc for k in ("winlog", "process", "host", "event")) and any(
        isinstance(doc.get(k), dict) for k in ("winlog", "process", "host", "event")
    ):
        return True
    return any(k.startswith(("winlog.", "process.", "event.code")) for k in doc)


def _alias_security_4688(fields: dict[str, Any]) -> None:
    """Windows Security 4688 uses different names for the Sysmon fields."""
    aliases = {
        "NewProcessName": "Image",
        "ParentProcessName": "ParentImage",
        "SubjectUserName": "User",
    }
    for src, dst in aliases.items():
        if src in fields and dst not in fields:
            fields[dst] = fields[src]


def normalise(raw: dict[str, Any], origin: str = "") -> Event:
    if _is_ecs(raw):
        fields = _from_ecs(_flatten(raw))
    else:
        fields = dict(raw)

    channel = fields.get("Channel")
    event_id = fields.get("EventID")
    computer = fields.get("Computer") or fields.get("Hostname") or "unknown-host"
    ts_raw = fields.get("@timestamp") or fields.get("UtcTime") or fields.get("TimeCreated")
    if not channel or event_id in (None, ""):
        raise EventFormatError(f"{origin}: event needs Channel and EventID")
    try:
        event_id = int(event_id)
    except (TypeError, ValueError) as exc:
        raise EventFormatError(f"{origin}: EventID {event_id!r} is not an integer") from exc
    if ts_raw is None:
        raise EventFormatError(f"{origin}: event needs @timestamp, UtcTime or TimeCreated")
    fields["EventID"] = event_id
    fields["Channel"] = channel
    fields["Computer"] = computer
    if channel == SECURITY and event_id == 4688:
        _alias_security_4688(fields)
    return Event(
        fields=fields,
        channel=channel,
        event_id=event_id,
        computer=str(computer),
        timestamp=parse_timestamp(ts_raw),
        source=classify(channel, event_id),
        origin=origin,
    )


# --------------------------------------------------------------------------
# File readers
# --------------------------------------------------------------------------

def _open_text(path: Path) -> io.TextIOBase:
    if path.suffix == ".gz":
        return io.TextIOWrapper(gzip.open(path, "rb"), encoding="utf-8")
    return open(path, encoding="utf-8")


def _base_suffix(path: Path) -> str:
    return path.with_suffix("").suffix if path.suffix == ".gz" else path.suffix


def _read_json(path: Path) -> Iterator[tuple[dict[str, Any], str]]:
    suffix = _base_suffix(path)
    with _open_text(path) as fh:
        if suffix in (".jsonl", ".ndjson"):
            for lineno, line in enumerate(fh, 1):
                line = line.strip()
                if not line or line.startswith("//"):
                    continue
                try:
                    yield json.loads(line), f"{path}:{lineno}"
                except json.JSONDecodeError as exc:
                    raise EventFormatError(f"{path}:{lineno}: {exc}") from exc
        else:
            data = json.load(fh)
            items = data if isinstance(data, list) else [data]
            for index, item in enumerate(items):
                yield item, f"{path}[{index}]"


def _read_evtx(path: Path) -> Iterator[tuple[dict[str, Any], str]]:
    try:
        import Evtx.Evtx as evtx  # python-evtx
    except ImportError as exc:  # pragma: no cover - optional dependency
        raise EventFormatError("reading .evtx needs python-evtx (pip install python-evtx)") from exc
    import xml.etree.ElementTree as ET

    ns = "{http://schemas.microsoft.com/win/2004/08/events/event}"
    with evtx.Evtx(str(path)) as log:
        for index, record in enumerate(log.records()):
            try:
                root = ET.fromstring(record.xml())
            except ET.ParseError:
                continue
            system = root.find(f"{ns}System")
            if system is None:
                continue
            doc: dict[str, Any] = {
                "EventID": (system.findtext(f"{ns}EventID") or "").strip(),
                "Channel": system.findtext(f"{ns}Channel"),
                "Computer": system.findtext(f"{ns}Computer"),
            }
            created = system.find(f"{ns}TimeCreated")
            if created is not None:
                doc["@timestamp"] = created.get("SystemTime")
            event_data = root.find(f"{ns}EventData")
            if event_data is not None:
                for data in event_data.findall(f"{ns}Data"):
                    name = data.get("Name")
                    if name:
                        doc[name] = data.text or ""
            user_data = root.find(f"{ns}UserData")
            if user_data is not None:
                for child in user_data.iter():
                    tag = child.tag.split("}", 1)[-1]
                    if len(child) == 0 and child.text and child.text.strip():
                        doc.setdefault(tag, child.text.strip())
            yield doc, f"{path}#{index}"


def iter_files(paths: Iterable[Path | str]) -> Iterator[Path]:
    exts = (".json", ".jsonl", ".ndjson", ".evtx", ".gz")
    for p in paths:
        p = Path(p)
        if p.is_dir():
            for child in sorted(p.rglob("*")):
                if child.is_file() and child.suffix in exts and not child.name.startswith("."):
                    yield child
        elif p.is_file():
            yield p


def load_events(paths: Iterable[Path | str], strict: bool = True) -> list[Event]:
    """Load and normalise every event under ``paths`` (files or directories)."""
    events: list[Event] = []
    for path in iter_files(paths):
        if path.name.endswith(".meta.json") or path.name == "corpus.json":
            continue
        reader = _read_evtx if path.suffix == ".evtx" else _read_json
        for raw, origin in reader(path):
            try:
                events.append(normalise(raw, origin))
            except EventFormatError:
                if strict:
                    raise
    events.sort(key=lambda e: e.timestamp)
    return events
