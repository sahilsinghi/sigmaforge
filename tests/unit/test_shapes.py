"""The schema shapers must agree with the live pySigma pipelines.

For every field used by the repository's rules, convert a probe rule through
each backend's pipeline and check the field name it queries exists in the
shaped document of a matching event. If pySigma changes a mapping, this
fails before the equivalence report starts showing mysterious misses.
"""

import re

import pytest
from sigma.collection import SigmaCollection
from sigma.plugins import InstalledSigmaPlugins

from conftest import security, sysmon
from sigmaforge.convert import resolve_pipelines
from sigmaforge.shapes import to_ecs, to_splunk, to_xdr

PROBES = [
    ("process_creation", None, 1, ["Image", "CommandLine", "ParentImage", "OriginalFileName", "Description", "User"]),
    ("process_access", None, 10, ["SourceImage", "TargetImage", "GrantedAccess"]),
    ("registry_set", None, 13, ["TargetObject", "Details", "Image"]),
    ("pipe_created", None, 17, ["PipeName", "Image"]),
    ("dns_query", None, 22, ["QueryName", "Image"]),
    (None, "security", 4732, ["TargetSid", "MemberSid", "IpAddress", "TargetUserName", "LogonType"]),
    (None, "system", 7045, ["ServiceName", "ImagePath"]),
]


@pytest.fixture(scope="module")
def plugins():
    return InstalledSigmaPlugins.autodiscover()


def _convert(plugins, target, pipelines, category, service, field):
    ls = f"category: {category}" if category else f"service: {service}"
    y = f"title: probe\nid: 11111111-2222-3333-4444-555555555555\nlogsource:\n  product: windows\n  {ls}\n" \
        f"detection:\n  sel:\n    {field}: 'probe'\n  condition: sel\n"
    backend = plugins.backends[target](processing_pipeline=resolve_pipelines(plugins, pipelines))
    return " ".join(str(q) for q in backend.convert(SigmaCollection.from_yaml(y)))


def _event(category, service, eid, field):
    if service == "security":
        return security(eid, **{field: "probe"})
    if service == "system":
        from sigmaforge.events import normalise

        return normalise({"EventID": eid, "Channel": "System", "Computer": "h", "@timestamp": "2026-10-01T00:00:00Z", field: "probe"})
    return sysmon(eid, **{field: "probe"})


@pytest.mark.parametrize("category,service,eid,fields", PROBES)
def test_ecs_shape_matches_pipeline(plugins, category, service, eid, fields):
    for field in fields:
        query = _convert(plugins, "lucene", ["sysmon", "ecs_windows"], category, service, field)
        m = re.search(r"([\w.]+):probe", query)
        assert m, query
        name = m.group(1).removesuffix(".caseless")
        doc = to_ecs(_event(category, service, eid, field))
        assert doc.get(name) == "probe", f"{field} -> {name} missing from ECS shape {sorted(doc)}"


@pytest.mark.parametrize("category,service,eid,fields", PROBES)
def test_splunk_shape_matches_pipeline(plugins, category, service, eid, fields):
    for field in fields:
        query = _convert(plugins, "splunk", ["sysmon", "splunk_windows"], category, service, field)
        m = re.search(r'([\w.]+)="probe"', query)
        assert m, query
        doc = to_splunk(_event(category, service, eid, field))
        assert doc.get(m.group(1)) == "probe"


def test_xdr_shape_matches_pipeline_for_process_and_registry(plugins):
    for category, eid, field, column in [
        ("process_creation", 1, "CommandLine", "ProcessCommandLine"),
        ("process_creation", 1, "ParentImage", "InitiatingProcessFolderPath"),
        ("registry_set", 13, "Details", "RegistryValueData"),
    ]:
        query = _convert(plugins, "kusto", ["microsoft_xdr"], category, None, field)
        assert column in query
        table, row = to_xdr(sysmon(eid, **{field: "probe"}))
        assert row[column] == "probe" and table in query


def test_xdr_registry_key_spelling_and_value_split():
    table, row = to_xdr(sysmon(13, TargetObject="HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run\\x", Details="y",
                               EventType="SetValue", Image="C:\\a.exe"))
    assert table == "DeviceRegistryEvents"
    assert row["RegistryKey"] == "HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run"
    assert row["RegistryValueName"] == "x"
    assert row["ActionType"] == "RegistryValueSet"
