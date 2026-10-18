"""Map raw Windows events onto Sigma log sources.

Sigma rules target *generic* log sources (``category: process_creation``)
or *services* (``service: security``). Telemetry arrives as concrete
channel + event ID pairs. This module is the single place that knows which
pair belongs to which Sigma log source, so the replay engine only offers a
rule the events its logsource covers - the same thing the ``sysmon`` and
``windows-logsources`` processing pipelines do for SIEM queries.
"""

from __future__ import annotations

from dataclasses import dataclass

SYSMON = "Microsoft-Windows-Sysmon/Operational"
SECURITY = "Security"
SYSTEM = "System"
POWERSHELL = "Microsoft-Windows-PowerShell/Operational"

# (channel, event id) -> Sigma category
CATEGORY_BY_EVENT: dict[tuple[str, int], str] = {
    (SYSMON, 1): "process_creation",
    (SYSMON, 2): "file_change",
    (SYSMON, 3): "network_connection",
    (SYSMON, 5): "process_termination",
    (SYSMON, 6): "driver_load",
    (SYSMON, 7): "image_load",
    (SYSMON, 8): "create_remote_thread",
    (SYSMON, 9): "raw_access_thread",
    (SYSMON, 10): "process_access",
    (SYSMON, 11): "file_event",
    (SYSMON, 12): "registry_add",
    (SYSMON, 13): "registry_set",
    (SYSMON, 14): "registry_rename",
    (SYSMON, 15): "create_stream_hash",
    (SYSMON, 17): "pipe_created",
    (SYSMON, 18): "pipe_created",
    (SYSMON, 19): "wmi_event",
    (SYSMON, 20): "wmi_event",
    (SYSMON, 21): "wmi_event",
    (SYSMON, 22): "dns_query",
    (SYSMON, 23): "file_delete",
    (SYSMON, 25): "process_tampering",
    (SYSMON, 26): "file_delete_detected",
    # Windows Security 4688 is the non-Sysmon source of process creation.
    (SECURITY, 4688): "process_creation",
    (POWERSHELL, 4104): "ps_script",
    (POWERSHELL, 4103): "ps_module",
}

# Sigma's umbrella categories: a registry_event rule covers 12/13/14.
UMBRELLA = {
    "registry_event": {"registry_add", "registry_set", "registry_rename", "registry_delete"},
    "pipe_created": {"pipe_created"},
}

SERVICE_BY_CHANNEL = {
    SECURITY: "security",
    SYSTEM: "system",
    SYSMON: "sysmon",
    POWERSHELL: "powershell",
    "Application": "application",
    "Microsoft-Windows-TaskScheduler/Operational": "taskscheduler",
    "Microsoft-Windows-Windows Defender/Operational": "windefend",
}


@dataclass(frozen=True)
class EventSource:
    product: str
    category: str | None
    service: str | None


def classify(channel: str, event_id: int) -> EventSource:
    """Return the Sigma log source an event belongs to."""
    return EventSource(
        product="windows",
        category=CATEGORY_BY_EVENT.get((channel, event_id)),
        service=SERVICE_BY_CHANNEL.get(channel),
    )


def rule_accepts(logsource, src: EventSource) -> bool:
    """Does a rule with ``logsource`` (a pySigma SigmaLogSource) see this event?"""
    if logsource.product and logsource.product != src.product:
        return False
    if logsource.category:
        wanted = UMBRELLA.get(logsource.category, {logsource.category})
        if src.category not in wanted:
            return False
    if logsource.service:
        if logsource.service != src.service:
            return False
    return bool(logsource.product or logsource.category or logsource.service)
