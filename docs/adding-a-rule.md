# Adding a rule

1. **Write the Sigma rule** under `rules/windows/<logsource>/`, named like SigmaHQ
   (`proc_creation_win_<what>.yml`). Tag ATT&CK v19 tactics and techniques.
2. **Declare how it is tested** in a `x_sigmaforge` block:

   ```yaml
   x_sigmaforge:
     owner: your.name
     confidence: medium          # low | medium | high
     noise_budget: 0.05          # max alerts per host per day on benign data
     tests:
       positive: [tests/positive/<rule file stem>]
       negative: [tests/negative/<rule file stem>]
       external:                 # optional real telemetry from the pinned dataset
         - dataset: evtx-attack-samples
           path: Execution/some_sample.evtx
           min_hits: 1
   ```
3. **Add positives**: one JSONL event per attack variant (`tests/positive/<stem>/*.jsonl`),
   with the fields Sysmon / Windows would record. Every event must match.
4. **Add near-miss negatives**: the benign strings closest to your pattern. They must not match.
5. **Run it**:

   ```bash
   sigmaforge lint
   sigmaforge test
   sigmaforge equivalence --opensearch http://localhost:9200   # optional locally, always in CI
   sigmaforge tune <rule>                                      # if it is noisy
   ```
6. **Open the PR.** CI posts the gate decision as a comment. When it merges, `main`
   regenerates `baseline/metrics.json` (`sigmaforge baseline update`) so the next PR is
   compared with it.

If a backend legitimately cannot match what Sigma means, document it in
`equivalence-exceptions.yml` with the reason and the exact expected difference.
