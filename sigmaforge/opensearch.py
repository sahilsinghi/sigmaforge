"""Replay converted Lucene queries in a real OpenSearch cluster.

The in-process Lucene evaluator is a model; this is the ground truth. The
corpus is reshaped into ECS documents, bulk-indexed into a throwaway index
whose template mirrors Winlogbeat's (keywords, plus lowercase-normalised
``.caseless`` multi-fields for the fields the ES backend queries that way),
and every rule's Lucene query is run as a ``query_string`` query. Hit sets
are compared document by document.

Standard library only (urllib), so CI needs nothing beyond the service
container: ``docker run -p 9200:9200 -e discovery.type=single-node
-e DISABLE_SECURITY_PLUGIN=true opensearchproject/opensearch:2``.
"""

from __future__ import annotations

import json
import urllib.error
import urllib.request
from typing import Any

from sigmaforge.shapes import ECS_CASELESS

INDEX = "sigmaforge-replay"


class OpenSearchError(Exception):
    pass


def _request(url: str, method: str = "GET", body: Any = None, ndjson: bool = False, timeout: int = 60) -> Any:
    data = None
    headers = {}
    if body is not None:
        if ndjson:
            data = body.encode("utf-8")
            headers["Content-Type"] = "application/x-ndjson"
        else:
            data = json.dumps(body).encode("utf-8")
            headers["Content-Type"] = "application/json"
    req = urllib.request.Request(url, data=data, method=method, headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:  # noqa: S310 - user-supplied lab URL
            text = resp.read().decode("utf-8")
    except urllib.error.HTTPError as exc:
        detail = exc.read().decode("utf-8", "replace")[:500]
        raise OpenSearchError(f"{method} {url}: HTTP {exc.code} {detail}") from exc
    except (urllib.error.URLError, OSError) as exc:
        raise OpenSearchError(f"{method} {url}: {exc}") from exc
    return json.loads(text) if text else None


def _nest(flat: dict[str, Any]) -> dict[str, Any]:
    """OpenSearch accepts dotted keys, but nesting avoids object/leaf clashes."""
    out: dict[str, Any] = {}
    for key, value in flat.items():
        parts = key.split(".")
        node = out
        for part in parts[:-1]:
            nxt = node.get(part)
            if not isinstance(nxt, dict):
                nxt = {}
                node[part] = nxt
            node = nxt
        node[parts[-1]] = value
    return out


def index_template() -> dict[str, Any]:
    keyword = {"type": "keyword", "ignore_above": 32766}
    caseless = {**keyword, "fields": {"caseless": {"type": "keyword", "normalizer": "lowercase", "ignore_above": 32766}}}
    properties: dict[str, Any] = {}
    for dotted in ECS_CASELESS:
        node = properties
        parts = dotted.split(".")
        for part in parts[:-1]:
            node = node.setdefault(part, {"properties": {}})["properties"]
        node[parts[-1]] = caseless
    properties["@timestamp"] = {"type": "date"}
    properties.setdefault("process", {"properties": {}})["properties"]["pid"] = {"type": "long"}
    properties.setdefault("destination", {"properties": {}})["properties"]["port"] = {"type": "long"}
    return {
        "settings": {
            "number_of_shards": 1,
            "number_of_replicas": 0,
            "max_result_window": 200000,
            "analysis": {"normalizer": {"lowercase": {"type": "custom", "filter": ["lowercase"]}}},
        },
        "mappings": {
            # Every string also gets a lowercase-normalised ".caseless" twin, which the
            # sigmaforge_ecs_caseless pipeline queries for case-insensitive matching.
            "dynamic_templates": [{"strings": {"match_mapping_type": "string", "mapping": caseless}}],
            "properties": properties,
        },
    }


class OpenSearchReplay:
    def __init__(self, url: str):
        self.url = url.rstrip("/")
        self.version = ""

    def available(self) -> bool:
        try:
            info = _request(self.url, timeout=5)
        except OpenSearchError:
            return False
        self.version = (info or {}).get("version", {}).get("number", "")
        return True

    def load(self, docs: list[dict[str, Any]]) -> None:
        try:
            _request(f"{self.url}/{INDEX}", method="DELETE")
        except OpenSearchError:
            pass
        _request(f"{self.url}/{INDEX}", method="PUT", body=index_template())
        batch: list[str] = []
        for i, doc in enumerate(docs):
            batch.append(json.dumps({"index": {"_index": INDEX, "_id": str(i)}}))
            batch.append(json.dumps(_nest(doc)))
            if len(batch) >= 4000:
                self._bulk(batch)
                batch = []
        if batch:
            self._bulk(batch)
        _request(f"{self.url}/{INDEX}/_refresh", method="POST")

    def _bulk(self, lines: list[str]) -> None:
        res = _request(f"{self.url}/_bulk", method="POST", body="\n".join(lines) + "\n", ndjson=True, timeout=300)
        if res and res.get("errors"):
            first = next((it for it in res["items"] if it.get("index", {}).get("error")), None)
            raise OpenSearchError(f"bulk indexing failed: {json.dumps(first)[:400]}")

    def hits(self, lucene: str) -> set[int]:
        ids: set[int] = set()
        body = {"query": {"query_string": {"query": lucene}}, "_source": False, "size": 10000,
                "sort": [{"_doc": "asc"}]}
        res = _request(f"{self.url}/{INDEX}/_search?scroll=1m", method="POST", body=body)
        while True:
            batch = res["hits"]["hits"]
            if not batch:
                break
            ids.update(int(h["_id"]) for h in batch)
            res = _request(f"{self.url}/_search/scroll", method="POST",
                           body={"scroll": "1m", "scroll_id": res["_scroll_id"]})
        return ids

    def cleanup(self) -> None:
        try:
            _request(f"{self.url}/{INDEX}", method="DELETE")
        except OpenSearchError:
            pass


def component_template_for_queries(queries: list[str]) -> dict[str, Any]:
    """Elasticsearch/OpenSearch component template for the ``.caseless`` fields.

    Real Winlogbeat indices map ECS fields explicitly, so a dynamic template is
    not enough: every field the converted rules query as ``<field>.caseless``
    gets an explicit lowercase-normalised keyword multi-field. Adding a
    multi-field to an existing field is a non-breaking mapping update; existing
    documents need an update-by-query (or the next index rollover) to populate it.
    """
    import re

    fields = sorted({m.group(1) for q in queries for m in re.finditer(r"([\w.@]+)\.caseless:", q)})
    properties: dict[str, Any] = {}
    for dotted in fields:
        node = properties
        parts = dotted.split(".")
        for part in parts[:-1]:
            node = node.setdefault(part, {"properties": {}})["properties"]
        node[parts[-1]] = {
            "type": "keyword",
            "ignore_above": 32766,
            "fields": {"caseless": {"type": "keyword", "normalizer": "sigmaforge_lowercase", "ignore_above": 32766}},
        }
    return {
        "template": {
            "settings": {"analysis": {"normalizer": {"sigmaforge_lowercase": {"type": "custom", "filter": ["lowercase"]}}}},
            "mappings": {"_meta": {"generator": "sigmaforge", "caseless_fields": fields}, "properties": properties},
        }
    }
