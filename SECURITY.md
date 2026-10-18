# Security

## Threat model

SigmaForge runs pull-request content (rules, test events and the package itself) in CI, so a pull request is treated as untrusted code.

| Concern | How it is handled |
|---|---|
| PR code reaching secrets | The PR-facing `test` job has a read-only token (plus `pull-requests: write` for its own comment) and does not persist git credentials. SIEM secrets exist only in `deploy.yml`, a reusable workflow called after the gate passes on a push to `main`. There is no `workflow_run` or `pull_request_target` trigger. |
| Write access from PR runs | Refreshing `baseline/metrics.json` happens in a separate `baseline` job that runs only on `main` and needs the gate to pass. It pushes with an explicit token. |
| Script injection in workflows | Every `${{ … }}` value reaches shell steps through `env:`, never interpolated into the script. |
| Mutable third-party actions | Every action is pinned to a commit SHA (tag in a comment). Dependabot proposes updates for actions and pip packages weekly. |
| Tampered test telemetry | EVTX-ATTACK-SAMPLES is pinned to a commit, and every file must match its Git blob hash. The benign baseline is generated deterministically and checked against a lock. |
| Hostile rule content | YAML is loaded with `safe_load`. The HTML report autoescapes rule text and has no `|safe` output. |

Checked with: bandit, semgrep (`p/python`, `p/github-actions`, `p/secrets`), zizmor and actionlint (all workflows clean), and pip-audit.

## Known residual risks

- **`diskcache` 5.6.3** (CVE-2025-69872, a transitive dependency of pySigma) stores its cache with pickle. Anyone who can write to `~/.cache/pysigma` can run code when pySigma reads it. No fixed release exists yet. That directory is writable only by your user, and CI runners start empty. Upgrade when pySigma ships a fix.
- **Rule regexes** run in the replay engine. A pathological pattern in a PR can only slow down that PR's own CI run.
- **Replay target.** The OpenSearch replay assumes a throwaway local container with the security plugin disabled. Never point `--opensearch` at a shared or production cluster.

## Reporting

Please open a private security advisory on the repository instead of a public issue.
