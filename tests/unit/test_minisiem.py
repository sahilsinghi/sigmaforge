"""The query-language oracles: semantics that differ between SIEMs."""

import pytest

from sigmaforge.minisiem import Unsupported, kql, lucene, spl


# -- Lucene / OpenSearch ---------------------------------------------------

def test_lucene_keyword_fields_are_case_sensitive_caseless_are_not():
    doc = {"process.command_line": "powershell -ENC abc", "process.executable": "C:\\X\\PowerShell.EXE"}
    assert not lucene.compile_query(r"process.command_line:*\ \-enc\ *")(doc)
    assert lucene.compile_query(r"process.command_line.caseless:*\ \-enc\ *")(doc)
    assert lucene.compile_query(r"process.executable.caseless:*\\powershell.exe")(doc)
    assert lucene.compile_query(r"process.executable.caseless:*\\POWERSHELL.EXE")(doc)


def test_lucene_regex_is_anchored_and_backslash_escapes_literally():
    doc = {"file.name": "\\svchost-HOST-8116-stdin"}
    assert lucene.compile_query(r"file.name:/\\[^\\]+-[^\\]+-[0-9]+-(stdin|stdout|stderr)/")(doc)
    assert not lucene.compile_query(r"file.name:/stdin/")(doc)  # implicitly anchored
    assert lucene.compile_query(r"file.name:/.*stdin/")(doc)
    # \d is a digit class in Lucene 9, but \b is just the letter "b" and (?i) is not syntax
    assert lucene.compile_query(r"file.name:/.*\d+.*/")(doc)
    assert not lucene.compile_query(r"file.name:/.*\bstdin/")(doc)
    with pytest.raises(Unsupported):
        lucene.compile_query(r"file.name:/(?i).*STDIN/")


def test_lucene_field_groups_not_and_phrases():
    doc = {"event.code": "17", "winlog.channel": "Microsoft-Windows-Sysmon/Operational",
           "process.pe.description": "Rsync for cloud storage"}
    q = r"winlog.channel:Microsoft\-Windows\-Sysmon\/Operational AND (event.code:(17 OR 18))"
    assert lucene.compile_query(q)(doc)
    assert lucene.compile_query('process.pe.description:"Rsync for cloud storage"')(doc)
    assert lucene.compile_query("NOT user.name:bob")(doc)  # missing field -> NOT matches


def test_lucene_refuses_ambiguous_mixed_operators():
    with pytest.raises(Unsupported):
        lucene.compile_query("a:1 AND b:2 OR c:3")


# -- Splunk ---------------------------------------------------------------

def test_spl_or_binds_tighter_than_implicit_and():
    run = spl.compile_query('Image="*\\\\certutil.exe" OR OriginalFileName="CertUtil.exe" '
                            'CommandLine="* -urlcache *" OR CommandLine="* /urlcache *"')
    hit = {"Image": "C:\\x\\certutil.exe", "CommandLine": "certutil /urlcache /f http://a", "__idx": 0}
    miss = {"Image": "C:\\x\\certutil.exe", "CommandLine": "certutil -hashfile a", "__idx": 1}
    assert [d["__idx"] for d in run([hit, miss])] == [0]


def test_spl_values_case_insensitive_and_not_matches_missing_field():
    run = spl.compile_query('source="WinEventLog:Security" EventCode=4732 NOT TargetUserName="x*"')
    docs = [{"source": "WinEventLog:Security", "EventCode": 4732, "__idx": 0},
            {"source": "winEVENTlog:security", "EventCode": "4732", "TargetUserName": "XYZ", "__idx": 1}]
    assert [d["__idx"] for d in run(docs)] == [0]


def test_spl_rex_eval_search_pipeline():
    q = ('source="WinEventLog:Microsoft-Windows-Sysmon/Operational" \n'
         '| rex field=PipeName "(?<PipeNameMatch>\\\\\\\\[^\\\\\\\\]+-[^\\\\\\\\]+-[0-9]+-(stdin|stdout|stderr))" \n'
         '| eval PipeNameCondition=if(isnotnull(PipeNameMatch), "true", "false") \n'
         '| search EventCode IN (17, 18) PipeName="\\\\PSEXESVC*" OR PipeNameCondition="true"')
    run = spl.compile_query(q)
    base = {"source": "WinEventLog:Microsoft-Windows-Sysmon/Operational", "EventCode": 17}
    docs = [{**base, "PipeName": "\\svchost-HOST-8116-stdin", "__idx": 0},
            {**base, "PipeName": "\\PSEXESVC", "__idx": 1},
            {**base, "PipeName": "\\lsass", "__idx": 2}]
    assert sorted(d["__idx"] for d in run(docs)) == [0, 1]


def test_spl_bin_uses_fixed_buckets():
    q = ('source="WinEventLog:Security" EventCode=4625 | bin _time span=5m '
         '| stats count as event_count by _time IpAddress | search event_count >= 10')
    run = spl.compile_query(q)
    # 12 failures from 10:03:30 every 15 s cross the 10:05 boundary: 6 + 6
    start = 1790935410  # 2026-10-02 10:03:30 UTC (bucket boundary every 300 s)
    start = start - start % 300 + 210
    docs = [{"source": "WinEventLog:Security", "EventCode": 4625, "IpAddress": "10.0.0.9",
             "_time": start + 15 * i, "__idx": i} for i in range(12)]
    assert run(docs) == []
    same_bucket = [{**d, "_time": start - 200 + 10 * d["__idx"]} for d in docs]
    assert len(run(same_bucket)) == 1


# -- KQL ------------------------------------------------------------------

def test_kql_string_operators_are_case_insensitive_except_cs_and_equals():
    _, pred = kql.compile_query('DeviceProcessEvents | where ProcessCommandLine contains " -enc " and FolderPath endswith "\\\\powershell.exe"')
    assert pred({"ProcessCommandLine": "powershell -ENC x", "FolderPath": "C:\\PowerShell.EXE"})
    _, eq = kql.compile_query('DeviceProcessEvents | where FileName == "cmd.exe"')
    assert not eq({"FileName": "CMD.EXE"})
    _, ieq = kql.compile_query('DeviceProcessEvents | where FileName =~ "cmd.exe"')
    assert ieq({"FileName": "CMD.EXE"})


def test_kql_has_no_wildcards_in_endswith():
    _, pred = kql.compile_query('DeviceRegistryEvents | where RegistryKey endswith "\\\\CurrentVersion\\\\Run*"')
    assert not pred({"RegistryKey": "HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run"})
    assert pred({"RegistryKey": "x\\CurrentVersion\\Run*"})


def test_kql_in_not_and_regex():
    _, pred = kql.compile_query(
        'DeviceProcessEvents | where (ProcessVersionInfoOriginalFileName in~ ("PowerShell.EXE", "pwsh.dll")) '
        'and (not(InitiatingProcessFolderPath startswith "C:\\\\Windows\\\\CCM\\\\")) and ProcessCommandLine matches regex "[A-Za-z0-9+/]{20,}"'
    )
    row = {"ProcessVersionInfoOriginalFileName": "powershell.exe", "InitiatingProcessFolderPath": "C:\\Windows\\explorer.exe",
           "ProcessCommandLine": "powershell -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBi"}
    assert pred(row)
    assert not pred({**row, "InitiatingProcessFolderPath": "C:\\Windows\\CCM\\CcmExec.exe"})


def test_kql_rejects_unmodelled_operators():
    with pytest.raises(Unsupported):
        kql.compile_query("DeviceProcessEvents | summarize count() by DeviceName")
