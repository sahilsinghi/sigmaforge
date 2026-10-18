# What the pipeline found

Things that only showed up because rules were replayed against real telemetry, near-miss
negatives and the converted queries themselves. Each one is reproducible from this repo.

## 1. Stock Elastic conversion is case-sensitive where Sigma is not

**Found by:** cross-backend replay (`sigmaforge equivalence`), confirmed in OpenSearch 2.19.

Sigma string matching is case-insensitive by specification. pySigma's `ecs_windows`
pipeline routes only `process.executable` and `process.parent.executable` through
lowercase-normalised `.caseless` multi-fields. Everything else (`process.command_line`,
`registry.path`, `winlog.event_data.*`) becomes a case-sensitive keyword or wildcard query.

| Rule | Missed by stock Lucene | Example |
|---|---|---|
| Encoded PowerShell | 2 of 5 hits | `-Enc`, `-ENCODEDCOMMAND` |
| Scheduled task with suspicious action | 6 of 8 (including a real EVTX sample) | `SCHTASKS /Create`, `schtasks.exe /Create` |
| Privileged group recon | 2 of 10 | `net group "Domain Admins" /domain` vs rule's `admins` |
| Run key in user-writable path | 5 of 11 (3 real samples) | `HKLM\SOFTWARE\...\Run` vs rule's `\Software\` |

**Fix shipped:** a `sigmaforge_ecs_caseless` processing pipeline (a pySigma transformation
that points every non-regex string comparison at `<field>.caseless`), an OpenSearch/Elastic
component template that adds those multi-fields (`sigmaforge export elastic-template`),
and the `lucene` backend now uses both. It returns hit sets identical to the Sigma engine on
every rule. The stock pipeline is kept as `lucene_stock` with the gaps documented and pinned.

## 2. The Defender XDR pipeline produces an unmatchable registry query

**Found by:** cross-backend replay.

`TargetObject|contains: '\Software\Microsoft\Windows\CurrentVersion\Run\'` is rewritten by
pySigma's `microsoft_xdr` pipeline into

```kql
RegistryKey endswith "\\Software\\Microsoft\\Windows\\CurrentVersion\\Run*"
```

KQL's `endswith` has no wildcards, so the asterisk is literal and the query can never match.
11 of 11 hits are missed. Documented in `equivalence-exceptions.yml`. Until it is fixed
upstream, XDR registry detections should be written against `RegistryKey` /
`RegistryValueName` directly.

## 3. Sysmon pads LSASS access masks in older versions

**Found by:** real EVTX samples.

Most write-ups give LSASS access masks as `0x1010` or `0x1fffff`. Every LSASS-access event
in EVTX-ATTACK-SAMPLES records them zero-padded (`0x00001010`, `0x001fffff`, `0x0000143a`),
and an exact match on the short form matches none of them (pinned by
`test_hex_strings_compare_as_strings_not_numbers`). The rule lists both spellings. A rule
with only the short form would pass every hand-written positive and miss every real
Mimikatz run in these samples.

## 4. Most real mshta abuse is a cached `.hta`, not a URL

**Found by:** real EVTX samples.

The obvious mshta rule looks for `http://`, `https://`, `javascript:` and `vbscript:` on the
command line. The SharpShooter sample instead runs
`mshta.exe "C:\Users\...\Temporary Internet Files\Content.IE5\...\update.hta"`, a file the
browser had already downloaded. A staged-path selection (`.hta` under Temporary Internet
Files, INetCache, Downloads, AppData, Temp, Public, ProgramData) and `-Embedding` (LethalHTA
over DCOM) were added. Four real samples now fire.

## 5. Renamed PsExec keeps its pipe naming scheme

**Found by:** real EVTX samples.

`psexec -r svchost` renames the service, so `\PSEXESVC` disappears. The per-session pipes
keep their shape, `\<service>-<HOST>-<PID>-stdin|stdout|stderr`, so the rule matches that
pattern with a regex. It is written without `^`/`$` because Lucene regexes are implicitly
anchored and treat `^`/`$` as literals (verified in OpenSearch).

## 6. Splunk correlations use fixed buckets

**Found by:** correlation replay through the SPL evaluator.

pySigma converts Sigma correlation timespans to `| bin _time span=10m | stats ...`. These are
clock-aligned buckets, not sliding windows. A 12-account password spray from 13:57:00 to
14:00:40 lands as 9 + 3 accounts in two buckets and never reaches the threshold of 10. The
sliding-window engine alerts. Documented with the exact scenario. The mitigation is
`streamstats time_window=10m` (not yet emitted by pySigma). `temporal_ordered`
(brute force *then* success) cannot be converted for Splunk, Lucene, ES|QL or KQL at all,
so that rule is tested only on the reference engine.

## 7. ATT&CK v19 moved techniques under existing rules

**Found by:** `sigma check` against the live ATT&CK feed.

ATT&CK v19 renamed *Defense Evasion* to *Stealth*, added *Defense Impairment* (TA0112) and
moved *Clear Windows Event Logs* from T1070.001 to T1685.005. Rules tagged against v18 fail
lint. The repo ships an ATT&CK snapshot (`sigmaforge attack refresh`) so coverage maps are
reproducible offline.

## 8. Lucene regex: what works and what silently does not

**Found by:** probing OpenSearch 2.19 while building the Lucene evaluator.

| Construct | Behaviour in OpenSearch 2.19 (Lucene 9.12) |
|---|---|
| `\d \w \s \D \W \S` | supported character classes |
| `\b`, `\A`, `\Z` | literal letters, so the pattern quietly matches nothing |
| `(?i)` and lookarounds | not syntax; match nothing |
| `^` `$` | literal characters; patterns are implicitly anchored |
| `@ & ~ # < >` | operators when all flags are on (the default) |

The linter flags all of these in `re` modifiers, because they convert without error and
then never match in Elastic.
