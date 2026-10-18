"""In-process evaluators for the query languages SigmaForge converts to.

These are *test oracles*, not SIEMs: each implements the subset of its
language that pySigma emits, with that engine's matching semantics
(case sensitivity, wildcard and regex anchoring, missing-field behaviour),
so a converted query can be replayed on the same events as the Sigma
engine without standing up Splunk, Elastic and Defender.

Anything outside the supported subset raises ``Unsupported`` and is
reported as "not evaluable" - never silently treated as a match or a miss.
The Lucene evaluator is cross-checked against a real OpenSearch cluster in
CI (``sigmaforge equivalence --opensearch``).
"""


class Unsupported(Exception):
    """The query uses syntax this evaluator does not implement."""
