"""The reference Sigma engine: modifier and condition semantics."""

from conftest import make_rule, security, sysmon

from sigmaforge.engine import compile_rule


def rule(detection: str, logsource: str = "category: process_creation"):
    return compile_rule(make_rule(f"""
title: t
id: 11111111-1111-1111-1111-111111111111
logsource:
  product: windows
  {logsource}
detection:
{detection}
"""))


def test_contains_is_case_insensitive_and_needs_whole_field_match():
    r = rule("  sel:\n    CommandLine|contains: ' -enc '\n  condition: sel")
    assert r.matches(sysmon(CommandLine="powershell -ENC abc"))
    assert not r.matches(sysmon(CommandLine="powershell -Encoding utf8"))


def test_endswith_and_list_values_are_or():
    r = rule("  sel:\n    Image|endswith:\n      - '\\cmd.exe'\n      - '\\pwsh.exe'\n  condition: sel")
    assert r.matches(sysmon(Image="C:\\Windows\\System32\\CMD.EXE"))
    assert r.matches(sysmon(Image="C:\\Program Files\\PowerShell\\7\\pwsh.exe"))
    assert not r.matches(sysmon(Image="C:\\cmd.exe.bak"))


def test_all_modifier_requires_every_value():
    r = rule("  sel:\n    CommandLine|contains|all: ['delete', 'shadows']\n  condition: sel")
    assert r.matches(sysmon(CommandLine="vssadmin delete shadows /all"))
    assert not r.matches(sysmon(CommandLine="vssadmin list shadows"))


def test_windash_expands_dash_variants():
    r = rule("  sel:\n    CommandLine|windash|contains: ' -urlcache '\n  condition: sel")
    assert r.matches(sysmon(CommandLine="certutil /urlcache /f http://x"))
    assert r.matches(sysmon(CommandLine="certutil \u2013urlcache -f http://x"))


def test_regex_is_case_sensitive_search_unless_i():
    r = rule("  sel:\n    PipeName|re: '-[0-9]+-(stdin|stdout)'\n  condition: sel", "category: pipe_created")
    assert r.matches(sysmon(17, PipeName="\\svc-HOST-123-stdin"))
    assert not r.matches(sysmon(17, PipeName="\\svc-HOST-123-STDIN"))
    ri = rule("  sel:\n    PipeName|re|i: 'stdin$'\n  condition: sel", "category: pipe_created")
    assert ri.matches(sysmon(17, PipeName="\\svc-HOST-123-STDIN"))


def test_cased_modifier_is_case_sensitive():
    r = rule("  sel:\n    CommandLine|cased: 'AbC'\n  condition: sel")
    assert r.matches(sysmon(CommandLine="AbC"))
    assert not r.matches(sysmon(CommandLine="abc"))


def test_cidr_number_null_exists_and_keywords():
    r = rule("  sel:\n    DestinationIp|cidr: '10.0.0.0/8'\n  condition: sel", "category: network_connection")
    assert r.matches(sysmon(3, DestinationIp="10.20.30.40"))
    assert not r.matches(sysmon(3, DestinationIp="192.168.1.1"))
    n = rule("  sel:\n    LogonType: 3\n  condition: sel", "service: security")
    assert n.matches(security(4625, LogonType="3"))
    nul = rule("  sel:\n    ParentCommandLine: null\n  condition: sel")
    assert nul.matches(sysmon(Image="x"))
    assert not nul.matches(sysmon(ParentCommandLine="y"))
    ex = rule("  sel:\n    Hashes|exists: true\n  condition: sel")
    assert ex.matches(sysmon(Hashes="SHA256=1"))
    kw = rule("  keywords:\n    - 'mimikatz'\n  condition: keywords")
    assert kw.matches(sysmon(CommandLine="C:\\tools\\Mimikatz.exe privilege::debug"))


def test_hex_strings_compare_as_strings_not_numbers():
    r = rule("  sel:\n    GrantedAccess: '0x1010'\n  condition: sel", "category: process_access")
    assert r.matches(sysmon(10, GrantedAccess="0x1010"))
    # Older Sysmon pads the mask; the rule must list both spellings (see the LSASS rule).
    assert not r.matches(sysmon(10, GrantedAccess="0x00001010"))


def test_logsource_routing():
    r = rule("  sel:\n    EventID: 1102\n  condition: sel", "service: security")
    assert r.matches(security(1102))
    assert not r.matches(sysmon(1, EventID=1102))


def test_filters_and_one_of_pattern():
    r = rule(
        "  sel_img:\n    Image|endswith: '\\powershell.exe'\n"
        "  sel_cli:\n    CommandLine|contains: ' -enc '\n"
        "  filter_sccm:\n    ParentImage: 'C:\\Windows\\CCM\\CcmExec.exe'\n"
        "  condition: all of sel_* and not 1 of filter_*"
    )
    base = dict(Image="C:\\x\\powershell.exe", CommandLine="powershell -enc AAA")
    assert r.matches(sysmon(**base, ParentImage="C:\\Windows\\explorer.exe"))
    assert not r.matches(sysmon(**base, ParentImage="C:\\Windows\\CCM\\CcmExec.exe"))


def test_security_4688_is_aliased_to_sysmon_names():
    r = rule("  sel:\n    Image|endswith: '\\whoami.exe'\n  condition: sel")
    assert r.matches(security(4688, NewProcessName="C:\\Windows\\System32\\whoami.exe", CommandLine="whoami"))
