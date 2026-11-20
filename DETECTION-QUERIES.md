# Etcd peer-status latch: detection and correlation queries

Look for a **current peer reported inactive by one member while traffic to that peer and Raft progress continue**, then correlate it with a delayed pipeline failure after stream recovery. A zero active-peer metric or an EOF alone does not identify the race.

Replace `<namespace>`, `<observer-pod>` and `<peer-member-id>` in these examples. The observer is the member reporting the incorrect status; the peer ID must belong to the **current etcd membership**, rather than a removed member with a lingering metric series. Scope every query to the same cluster.

Exporter labels are case-sensitive:

| Metric family | Local/remote identity |
|---|---|
| `etcd_network_active_peers`, `etcd_network_disconnected_peers_total` | `Local`, `Remote` |
| `etcd_network_peer_sent_bytes_total`, `etcd_network_peer_sent_failures_total`, RTT histogram | `To` |
| `etcd_network_peer_received_bytes_total` | `From` |

The examples assume scrape labels `namespace`, `pod` and `instance` identify the reporting endpoint. Adapt selectors and vector matching to your labels; include a cluster label in both where necessary. Missing series or insufficient samples mean unknown, not healthy. Use populated windows without member restarts when assessing persistence and progress.

## PromQL

### Find the inactive direction

```promql
etcd_network_active_peers{
  namespace="<namespace>",
  pod="<observer-pod>",
  Remote="<peer-member-id>"
} == 0
```

The returned `Local` and `Remote` labels identify the direction. Check other members' views separately; the disagreement can be asymmetric.

### Correlate sustained inactivity with outgoing traffic

```promql
(
  max_over_time(etcd_network_active_peers{
    namespace="<namespace>",
    pod="<observer-pod>"
  }[5m]) == 0
)
and on(namespace, pod, instance, Remote)
(
  label_replace(
    increase(etcd_network_peer_sent_bytes_total{
      namespace="<namespace>",
      pod="<observer-pod>"
    }[5m]),
    "Remote", "$1", "To", "(.+)"
  ) > 0
)
```

This returns peer directions whose status stayed zero in the available samples while the **same exporter** reported outgoing payload bytes to that peer. `label_replace` aligns `To` with `Remote` before matching. This is a candidate detector; confirm current membership and the logs below. For alerting, require continuous sample coverage and a sustained duration, rather than firing on a newly appearing series.

### Check traffic and independent reachability for that peer

Outgoing payload bytes during the window:

```promql
increase(etcd_network_peer_sent_bytes_total{
  namespace="<namespace>",pod="<observer-pod>",To="<peer-member-id>"
}[5m])
```

Incoming payload bytes:

```promql
increase(etcd_network_peer_received_bytes_total{
  namespace="<namespace>",pod="<observer-pod>",From="<peer-member-id>"
}[5m])
```

Successful RTT probe observations:

```promql
increase(etcd_network_peer_round_trip_time_seconds_bucket{
  namespace="<namespace>",pod="<observer-pod>",
  To="<peer-member-id>",le="+Inf"
}[5m])
```

Positive byte deltas support functioning transport. Positive RTT counts show successful independent probes; RTT probes alone do not prove Raft replication.

### Locate the failure transition

```promql
increase(etcd_network_disconnected_peers_total{
  namespace="<namespace>",pod="<observer-pod>",Remote="<peer-member-id>"
}[5m])
```

```promql
increase(etcd_network_peer_sent_failures_total{
  namespace="<namespace>",pod="<observer-pod>",To="<peer-member-id>"
}[5m])
```

These counters help locate the transition but are not race-specific. They can stop increasing while the incorrect inactive status persists. Search an earlier window if the latch is already established.

### Corroborate continued Raft progress across members

```promql
etcd_server_has_leader{namespace="<namespace>"}
```

```promql
delta(etcd_server_proposals_applied_total{namespace="<namespace>"}[5m])
```

Expect `has_leader=1` and positive applied-proposal deltas on the participating members, including the reportedly inactive peer. In etcd 3.5.26, `etcd_server_proposals_applied_total` is exported as a **gauge**, so use `delta`, despite its `_total` suffix. Compare the per-member series; do not sum away a stalled member. Leader presence alone does not establish health, quorum or consistent replication, and proposal progress is not a per-peer transport measurement.

## Log queries

### Build the peer's ordered transport timeline — LogQL

Adapt stream labels to the logging deployment. Query the **observer Pod's etcd container**, using a time range covering both the reconnect and subsequent metric mismatch:

```logql
{namespace="<namespace>",pod="<observer-pod>",container="etcd"}
  |= "<peer-member-id>"
  |~ "peer became active|peer became inactive|established TCP streaming connection|lost TCP streaming connection"
```

Look for this order:

1. `peer became active` and stream-established messages for the peer.
2. A **later** `peer became inactive (message send to peer failed)` whose error mentions a pipeline request.
3. No subsequent activation, while the metric mismatch and continued progress persist.

A stream can activate status before the delayed pipeline error deactivates it. Normal traffic on an already established stream need not produce new connection-established logs, so continued traffic must be checked using metrics or socket counters.

### Isolate the pipeline-induced deactivation — LogQL

```logql
{namespace="<namespace>",pod="<observer-pod>",container="etcd"}
  |= "<peer-member-id>"
  |= "peer became inactive"
  |= "on pipeline"
```

Typical error fragment:

```text
failed to write <peer-member-id> on pipeline (... EOF ...)
```

Timeouts or TCP aborts can produce the same ordering; EOF is not required. This query targets the pipeline variant. Other workers sharing peer status can also deactivate it, so keep the broader timeline query when investigating a mismatch without a pipeline match.

### Extract the same timeline from JSON log files — jq

For one member's raw JSON etcd logs, one JSON object per line:

```sh
jq -Rr --arg peer '<peer-member-id>' '
  fromjson?
  | select(."peer-id" == $peer or ."remote-peer-id" == $peer)
  | select((.msg // "") | test("peer became|established TCP streaming connection|lost TCP streaming connection"))
  | [.ts, .msg, (."peer-id" // ."remote-peer-id"), (.error // "")]
  | @tsv
' observer-etcd.log
```

The filter ignores non-JSON lines. Remove runtime-added timestamp/prefix text before using it on prefixed logs. Sort or inspect the resulting events by timestamp if the source merged multiple streams.

### Correlate downstream recovery failures — optional

Search the relevant recovery/controller/client log streams for:

```text
etcdserver: unhealthy cluster
```

Correlate the request's destination member and time with that member's inactive-peer view. This error is supporting impact evidence, not a diagnosis by itself, and need not occur until a membership operation is attempted. Do not issue a membership mutation solely to test detection.

## Interpretation

The strongest evidence combines **current-member status stuck at zero**, **continued payload and per-member Raft progress**, and **a stream activation followed by a later deactivating pipeline error without subsequent activation**. Ordinary restarts, actual partitions and removed-member series must be excluded. Absence of a matching log in a short retention/window does not exclude an older latch.
