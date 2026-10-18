"""SigmaForge: a detection-as-code pipeline for Sigma rules.

Rules live in Git as Sigma YAML. Every change is linted, converted to several
SIEM query languages, replayed against labelled attack telemetry (must fire)
and a benign baseline (must stay inside its noise budget), and mapped onto
MITRE ATT&CK. A rule that stops firing or starts flooding cannot be merged.
"""

__version__ = "0.1.0"
