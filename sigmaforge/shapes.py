"""Reshape canonical events into what each SIEM would actually store.

The same Sysmon event looks different in every backend:

* Splunk (Sysmon add-on): EventData names kept, ``source`` + ``EventCode``
* Elastic / OpenSearch (Winlogbeat 7+, ECS): ``process.executable``,
  ``registry.path``, everything else under ``winlog.event_data.*``
* Microsoft Defender XDR: different *tables* per event type, with their own
  column names, value vocabularies (``ActionType = RegistryValueSet``) and
  registry key spelling (``HKEY_LOCAL_MACHINE`` instead of ``HKLM``)

The mappings below mirror the pySigma processing pipelines the converter
uses (they were derived by converting probe rules through each pipeline;
``tests/unit/test_shapes.py`` re-checks them against the live pipelines).
Replaying converted queries on these shapes is what exposes field-mapping
mistakes that a pure Sigma matcher can never see.
"""

from __future__ import annotations

from typing import Any

from sigmaforge.events import Event

# --------------------------------------------------------------------------
# Splunk
# --------------------------------------------------------------------------

def to_splunk(ev: Event) -> dict[str, Any]:
    doc = {k: v for k, v in ev.fields.items() if k not in ("EventID", "Channel", "@timestamp")}
    doc["source"] = f"WinEventLog:{ev.channel}"
    doc["EventCode"] = ev.event_id
    doc["_time"] = ev.epoch
    doc["host"] = ev.computer
    return doc


# --------------------------------------------------------------------------
# Elastic Common Schema (Winlogbeat 7+, as mapped by pySigma's ecs_windows)
# --------------------------------------------------------------------------

ECS_COMMON = {
    "User": "user.name",
}
ECS_BY_CATEGORY: dict[str | None, dict[str, str]] = {
    "process_creation": {
        "Image": "process.executable",
        "CommandLine": "process.command_line",
        "ParentImage": "process.parent.executable",
        "ParentCommandLine": "process.parent.command_line",
        "OriginalFileName": "process.pe.original_file_name",
        "Description": "process.pe.description",
        "CurrentDirectory": "process.working_directory",
        "ProcessId": "process.pid",
    },
    "process_access": {"SourceImage": "process.executable"},
    "registry_set": {"TargetObject": "registry.path", "Image": "process.executable"},
    "registry_add": {"TargetObject": "registry.path", "Image": "process.executable"},
    "pipe_created": {"PipeName": "file.name", "Image": "process.executable"},
    "dns_query": {"QueryName": "dns.question.name", "Image": "process.executable", "QueryStatus": "sysmon.dns.status"},
    "network_connection": {
        "DestinationIp": "destination.ip",
        "DestinationPort": "destination.port",
        "DestinationHostname": "destination.domain",
        "SourceIp": "source.ip",
        "Image": "process.executable",
    },
}
ECS_BY_SERVICE = {
    "security": {"IpAddress": "source.ip", "SubjectUserName": "user.name", "WorkstationName": "source.domain"},
}
# Fields the ES backend queries through a lowercase-normalised ".caseless"
# multi-field. The OpenSearch index template must define these.
ECS_CASELESS = ("process.executable", "process.parent.executable")


def ecs_mapping(ev: Event) -> dict[str, str]:
    mapping: dict[str, str] = {}
    if ev.channel.startswith("Microsoft-Windows-Sysmon"):
        mapping.update(ECS_COMMON)
    mapping.update(ECS_BY_CATEGORY.get(ev.source.category, {}))
    mapping.update(ECS_BY_SERVICE.get(ev.source.service or "", {}))
    return mapping


def _set(doc: dict[str, Any], dotted: str, value: Any) -> None:
    doc[dotted] = value


def to_ecs(ev: Event) -> dict[str, Any]:
    """Flat dotted-key ECS document (OpenSearch accepts dotted keys)."""
    mapping = ecs_mapping(ev)
    doc: dict[str, Any] = {
        "@timestamp": ev.timestamp.isoformat(),
        "winlog.channel": ev.channel,
        "event.code": str(ev.event_id),
        "host.name": ev.computer,
        "winlog.computer_name": ev.computer,
    }
    for key, value in ev.fields.items():
        if key in ("EventID", "Channel", "Computer", "@timestamp"):
            continue
        target = mapping.get(key)
        if target:
            _set(doc, target, value if isinstance(value, (int, float)) and target.endswith(("port", "pid")) else str(value))
        else:
            _set(doc, f"winlog.event_data.{key}", "" if value is None else str(value))
    return doc


# --------------------------------------------------------------------------
# Microsoft Defender XDR advanced hunting tables
# --------------------------------------------------------------------------

XDR_TABLE = {
    "process_creation": "DeviceProcessEvents",
    "registry_set": "DeviceRegistryEvents",
    "registry_add": "DeviceRegistryEvents",
    "registry_event": "DeviceRegistryEvents",
    "network_connection": "DeviceNetworkEvents",
    "image_load": "DeviceImageLoadEvents",
    "file_event": "DeviceFileEvents",
}
REGISTRY_HIVES = (
    ("HKLM\\", "HKEY_LOCAL_MACHINE\\"),
    ("HKU\\", "HKEY_CURRENT_USER\\"),
    ("HKCU\\", "HKEY_CURRENT_USER\\"),
    ("HKCR\\", "HKEY_CLASSES_ROOT\\"),
)
REGISTRY_ACTIONS = {"SetValue": "RegistryValueSet", "CreateKey": "RegistryKeyCreated", "DeleteValue": "RegistryValueDeleted",
                    "DeleteKey": "RegistryKeyDeleted", "RenameKey": "RegistryKeyRenamed"}


def _split_account(value: Any) -> tuple[str, str]:
    text = str(value or "")
    if "\\" in text:
        domain, name = text.split("\\", 1)
        return domain, name
    return "", text


def _basename(path: Any) -> str:
    return str(path or "").rsplit("\\", 1)[-1]


def to_xdr(ev: Event) -> tuple[str, dict[str, Any]] | None:
    """Return (table, row) or None when XDR has no table for this event type."""
    table = XDR_TABLE.get(ev.source.category or "")
    if table is None or not ev.channel.startswith("Microsoft-Windows-Sysmon"):
        return None
    f = ev.fields
    row: dict[str, Any] = {"Timestamp": ev.epoch, "DeviceName": ev.computer}
    if table == "DeviceProcessEvents":
        domain, name = _split_account(f.get("User"))
        pdomain, pname = _split_account(f.get("ParentUser") or f.get("User"))
        row.update(
            ActionType="ProcessCreated",
            FolderPath=f.get("Image"),
            FileName=_basename(f.get("Image")),
            ProcessCommandLine=f.get("CommandLine"),
            ProcessVersionInfoOriginalFileName=f.get("OriginalFileName"),
            ProcessVersionInfoFileDescription=f.get("Description"),
            ProcessIntegrityLevel=f.get("IntegrityLevel"),
            ProcessId=f.get("ProcessId"),
            AccountDomain=domain,
            AccountName=name,
            InitiatingProcessFolderPath=f.get("ParentImage"),
            InitiatingProcessFileName=_basename(f.get("ParentImage")),
            InitiatingProcessCommandLine=f.get("ParentCommandLine"),
            InitiatingProcessAccountDomain=pdomain,
            InitiatingProcessAccountName=pname,
        )
    elif table == "DeviceRegistryEvents":
        target = str(f.get("TargetObject") or "")
        for short, long in REGISTRY_HIVES:
            if target.upper().startswith(short):
                target = long + target[len(short):]
                break
        key, _, value_name = target.rpartition("\\")
        domain, name = _split_account(f.get("User"))
        row.update(
            ActionType=REGISTRY_ACTIONS.get(str(f.get("EventType")), str(f.get("EventType") or "")),
            RegistryKey=key,
            RegistryValueName=value_name,
            RegistryValueData=f.get("Details"),
            InitiatingProcessFolderPath=f.get("Image"),
            InitiatingProcessFileName=_basename(f.get("Image")),
            InitiatingProcessAccountDomain=domain,
            InitiatingProcessAccountName=name,
        )
    elif table == "DeviceNetworkEvents":
        row.update(
            ActionType="ConnectionSuccess",
            RemoteIP=f.get("DestinationIp"),
            RemotePort=f.get("DestinationPort"),
            RemoteUrl=f.get("DestinationHostname"),
            LocalIP=f.get("SourceIp"),
            LocalPort=f.get("SourcePort"),
            InitiatingProcessFolderPath=f.get("Image"),
            InitiatingProcessFileName=_basename(f.get("Image")),
        )
    else:  # image_load / file_event - minimal columns
        row.update(
            FolderPath=f.get("ImageLoaded") or f.get("TargetFilename"),
            FileName=_basename(f.get("ImageLoaded") or f.get("TargetFilename")),
            InitiatingProcessFolderPath=f.get("Image"),
        )
    return table, row
