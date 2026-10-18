"""Sigma v2 correlations on the local engine."""

from datetime import datetime, timedelta, timezone

from sigma.collection import SigmaCollection

from conftest import security
from sigmaforge.correlation import CorrelationEngine

RULES = """
title: Failed logon
id: 0e95725d-7320-415d-80f7-004da920fc11
name: failed
logsource: {product: windows, service: security}
detection:
  sel: {EventID: 4625}
  condition: sel
---
title: Success
id: 0e95725d-7320-415d-80f7-004da920fc14
name: success
logsource: {product: windows, service: security}
detection:
  sel: {EventID: 4624}
  condition: sel
---
title: Burst
id: 0e95725d-7320-415d-80f7-004da920fc12
name: burst
correlation:
  type: event_count
  rules: [failed]
  group-by: [IpAddress]
  timespan: 5m
  condition: {gte: 10}
---
title: Spray
id: 0e95725d-7320-415d-80f7-004da920fc15
name: spray
correlation:
  type: value_count
  rules: [failed]
  group-by: [IpAddress]
  timespan: 10m
  condition: {gte: 5, field: TargetUserName}
---
title: Burst then success
id: 0e95725d-7320-415d-80f7-004da920fc13
name: burst_success
correlation:
  type: temporal_ordered
  rules: [burst, success]
  group-by: [IpAddress]
  timespan: 10m
"""

T0 = datetime(2026, 10, 1, 10, 3, 30, tzinfo=timezone.utc)


def _iso(t):
    return t.strftime("%Y-%m-%dT%H:%M:%SZ")


def rules():
    coll = SigmaCollection.from_yaml(RULES)
    return {r.name: r for r in coll.rules}


def failures(n, ip="10.0.0.9", spacing=15, users=None):
    return [security(4625, ts=_iso(T0 + timedelta(seconds=spacing * i)), IpAddress=ip,
                     TargetUserName=(users[i] if users else "administrator")) for i in range(n)]


def test_event_count_uses_sliding_windows_across_clock_buckets():
    # 12 failures from 10:03:30 straddle 10:05:00; a sliding window still sees >= 10
    alerts = CorrelationEngine().evaluate(rules()["burst"], failures(12))
    assert len(alerts) == 1
    assert alerts[0].group == {"IpAddress": "10.0.0.9"}


def test_event_count_respects_timespan_and_groups():
    slow = failures(12, spacing=60)  # 12 failures over 11 minutes: never 10 within 5m
    assert CorrelationEngine().evaluate(rules()["burst"], slow) == []
    mixed = failures(6, ip="10.0.0.1") + failures(6, ip="10.0.0.2")
    assert CorrelationEngine().evaluate(rules()["burst"], sorted(mixed, key=lambda e: e.timestamp)) == []


def test_value_count_counts_distinct_values():
    users = [f"user{i}" for i in range(6)]
    assert len(CorrelationEngine().evaluate(rules()["spray"], failures(6, users=users))) == 1
    assert CorrelationEngine().evaluate(rules()["spray"], failures(6)) == []


def test_temporal_ordered_requires_order_and_window():
    events = failures(12) + [security(4624, ts=_iso(T0 + timedelta(minutes=4)), IpAddress="10.0.0.9")]
    assert len(CorrelationEngine().evaluate(rules()["burst_success"], events)) == 1
    before = [security(4624, ts=_iso(T0 - timedelta(minutes=1)), IpAddress="10.0.0.9")] + failures(12)
    assert CorrelationEngine().evaluate(rules()["burst_success"], before) == []
    late = failures(12) + [security(4624, ts=_iso(T0 + timedelta(minutes=30)), IpAddress="10.0.0.9")]
    assert CorrelationEngine().evaluate(rules()["burst_success"], late) == []
