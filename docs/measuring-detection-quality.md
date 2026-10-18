# How I measure detection quality

A detection rule makes two promises: it fires when the attack happens, and it stays quiet
the rest of the time. Most rule repositories test neither. SigmaForge tests both on every
pull request and turns the results into numbers that can block a merge. This page explains
those numbers and where they stop being trustworthy.

## The four questions every rule has to answer

| Question | Evidence | Metric | Gate |
|---|---|---|---|
| Does it fire on the attack? | Labelled positive events (Atomic Red Team style), one file per variant | **True-positive rate** = matched positive events ÷ positive events | must be 100% (configurable per rule with `min_tpr`) |
| Does it fire on *real* attack telemetry, not just the events I wrote? | Public EVTX samples pinned to a commit and verified by Git blob hash | samples with ≥ `min_hits` matches | every declared sample must pass |
| Does it stay quiet on things that look almost the same? | Labelled near-miss negatives (`-Encoding UTF8` for an `-enc` rule, `vssadmin list shadows` for a shadow-copy deletion rule) | matches on negatives | must be 0 |
| How loud is it on a normal day? | Benign baseline: a week or more of normal activity | **alerts per host per day** = benign alerts ÷ host-days | must stay ≤ the rule's `noise_budget` |

Correlation rules (brute force then success, password spray) are scored by **scenario**:
each positive file must raise at least one alert and each negative file none.

### Why alerts per host per day

Analysts experience noise as a rate, and fleets differ in size. Dividing benign alerts by
**host-days** (distinct host × calendar day pairs actually present in the corpus) gives a
number that transfers: a budget of 0.05 means "about one alert per 20 hosts per day", which
is 50 alerts a day on a 1,000-host estate. The budget is set by the rule author in the
rule (`x_sigmaforge.noise_budget`), so the trade-off is reviewed together with the logic.

The denominator comes from the data, not from a config file, so dropping a real export
from a lab VM into `tests/benign/real/` automatically changes it.

### Why near-miss negatives matter more than the benign baseline

Benign baselines catch *volume*; they rarely contain the specific benign string that
breaks a rule. Hand-written near-misses do. In the example PR
([docs/example-pr.md](example-pr.md)) a "simplified" encoded-PowerShell rule still passed
all positives. It failed first on the near-miss file (`-Encoding UTF8`, `-ExecutionPolicy`)
and only then on noise (1.79 alerts/host/day against a 0.05 budget).

## Quality score and coverage

Tagging a rule `attack.t1059.001` costs nothing, and coverage maps built from tags
overstate what a SOC can actually detect. SigmaForge colours a technique only when an
alerting rule tagged with it **passes every test**, and the colour is earned:

```
quality = confidence × evidence × specificity × headroom
```

| Factor | Values | Why |
|---|---|---|
| confidence | low 0.5 · medium 0.75 · high 1.0 | the author's own judgement of the logic, declared in the rule |
| evidence | 0.4 for one positive, +0.1 per extra positive (max +0.3), +0.3 if real public telemetry fires it | many variants and real artefacts beat one hand-written event |
| specificity | 1.0 with near-miss negatives, 0.85 without | an untested false-positive surface is a risk |
| headroom | 1.0 if noise ≤ half the budget, else 0.9 | a rule at its limit will page someone soon |

A technique's score combines its rules as `1 − ∏(1 − qᵢ)`: a second decent rule adds
coverage, ten weak ones never reach 100. Building-block rules (inputs to correlations)
never count. Techniques whose rules fail are exported to the ATT&CK Navigator layer in
grey with the reason, so the map shows the gap instead of hiding it.

The weights are deliberately simple and visible in every report row
(`quality 0.75 = confidence 0.75 × evidence 1.0 × specificity 1.0 × headroom 1.0`). They are
a ranking aid, not a probability of detection.

## Does the converted query match what the rule means?

A Sigma rule is only as good as its translation. SigmaForge replays every converted query
on the **same events** the reference engine saw, reshaped into each SIEM's schema:

* **Splunk SPL**: Sysmon add-on field names, `source` / `EventCode`
* **Elastic / OpenSearch Lucene**: ECS / Winlogbeat 7+ documents, executed in-process and in a
  real OpenSearch 2.19 cluster in CI
* **Microsoft Defender XDR KQL**: `DeviceProcessEvents` / `DeviceRegistryEvents` rows with
  XDR's own column names and value spellings

Each rule × backend is `identical`, `documented` (a difference with a written reason *and*
its exact size pinned in `equivalence-exceptions.yml`), `mismatch` (blocks the merge) or
`unsupported`. On the current rule set: **61 identical, 6 documented, 0 undocumented**, and
OpenSearch returned exactly the modelled hit set for **36/36** Lucene queries.

What it found is in [findings.md](findings.md). The biggest finding: with pySigma's stock ECS
pipeline, Lucene matching on `process.command_line`, `registry.path` and most
`winlog.event_data.*` fields is case-sensitive. That silently loses `-ENC`,
`SCHTASKS /Create` and `HKLM\SOFTWARE\...` variants that the Sigma rule, which is
case-insensitive by specification, catches.

## Limits — read these before quoting any number

* **The benign baseline is synthetic by default.** It is a seeded simulation of a 12-host
  office designed to contain the things that make real rules noisy (per-user Run keys,
  SCCM encoded PowerShell, admins running `whoami /groups` and PsExec, a service account
  failing every 15 minutes). It is not a substitute for a real Sysmon VM baseline. Treat its
  alerts/host/day as a *regression signal* (did this change make the rule louder?) more than
  as a production forecast. `scripts/Export-SysmonBaseline.ps1` exports a real one.
* **Small samples are noisy.** With 168 host-days a single alert is 0.006/host/day. Budgets
  below ~0.01 cannot be distinguished from zero on this corpus.
* **Public attack samples are biased** towards loud, well-known tools (Mimikatz, Impacket,
  Metasploit, Atomic Red Team). Firing on them proves a rule recognises real artefacts, not
  that it catches a careful operator. 28/28 real samples passing is a floor, not a ceiling.
* **Positives are written by the rule author.** A rule and its own test data share the
  author's blind spots. The real-telemetry samples and the near-miss negatives are there to
  push back on that, and the mshta and Sysmon-padding fixes (see findings) came from them.
* **Coverage is about techniques, not procedures.** T1059.001 "covered" means one specific
  PowerShell behaviour is detected, not PowerShell abuse in general.
* **Evaluators are models.** The SPL and KQL evaluators implement only the subset pySigma
  emits, and anything else is reported as "not evaluable". The Lucene evaluator is checked
  against real OpenSearch every CI run; SPL and KQL are not checked against live Splunk or
  Defender.
