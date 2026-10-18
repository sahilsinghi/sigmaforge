"""SigmaForge's own pySigma processing pipelines.

``sigmaforge_ecs_caseless`` fixes a finding of the equivalence harness: with
the stock ``ecs_windows`` pipeline, most string fields (``process.command_line``,
``registry.path``, ``winlog.event_data.*``) are queried as case-sensitive
keywords, so the converted Lucene query misses ``-ENC`` or ``SCHTASKS /Create``
that the Sigma rule (case-insensitive by specification) catches.

The pipeline points every string comparison at a ``<field>.caseless``
multi-field - a keyword with a lowercase normalizer, which OpenSearch and
Elasticsearch apply to both the stored value and the query term. Regular
expressions keep the original field, because Sigma regexes are
case-sensitive. The index template in ``sigmaforge.opensearch`` defines the
multi-field for every string.
"""

from __future__ import annotations

from dataclasses import dataclass

from sigma.processing.pipeline import ProcessingItem, ProcessingPipeline
from sigma.processing.transformations.base import DetectionItemTransformation
from sigma.rule import SigmaDetectionItem
from sigma.types import SigmaExpansion, SigmaString

NON_STRING_FIELDS = frozenset({
    "winlog.channel", "event.code", "process.pid", "process.parent.pid",
    "destination.port", "source.port", "destination.ip", "source.ip",
})


@dataclass
class CaselessFieldTransformation(DetectionItemTransformation):
    """Append ``.caseless`` to fields compared against (non-regex) strings."""

    def apply_detection_item(self, detection_item: SigmaDetectionItem):
        field = detection_item.field
        if field is None or field.endswith(".caseless") or field in NON_STRING_FIELDS:
            return None
        values = detection_item.value
        if not values or not all(isinstance(v, (SigmaString, SigmaExpansion)) for v in values):
            return None
        detection_item.field = f"{field}.caseless"
        self.processing_item_applied(detection_item)
        return None


def ecs_caseless_pipeline() -> ProcessingPipeline:
    return ProcessingPipeline(
        name="SigmaForge: query lowercase-normalised .caseless multi-fields",
        priority=100,
        items=[ProcessingItem(identifier="sigmaforge_ecs_caseless", transformation=CaselessFieldTransformation())],
    )


CUSTOM_PIPELINES = {"sigmaforge_ecs_caseless": ecs_caseless_pipeline}
