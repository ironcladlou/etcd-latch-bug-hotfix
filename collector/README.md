# Etcd reproducer prerequisite collection

Run the collector from each serving etcd host:

```sh
sudo bash collect-etcd-host.sh --include-binary > collection.json
```

The collector emits one JSON report on stdout and saves the identical
`report.json` in an archive. Send back the files named by `artifacts.archive`
and `artifacts.checksum`:

```sh
python3 -c 'import json; r=json.load(open("collection.json")); print(r["artifacts"]["archive"]); print(r["artifacts"]["checksum"])'
```

The optional executable lets us reproduce the exact build and validate its
SHA-256. Omit `--include-binary` if initially sharing JSON only. Reports contain
internal names, addresses and file paths. Private keys, datastore files, full
CRI responses and unrelated environment settings are excluded.

## What is collected and why

Each collection operation has a named function with its purpose in a docstring.
`collect()` shows the collection order. The [example report](examples/README.md)
shows the resulting JSON.

| Evidence | Purpose |
| --- | --- |
| Host kernel, architecture and OS identity/version | Match the platform |
| Container image and process identity | Identify the selected etcd instance |
| Allowlisted etcd environment settings and flags | Match endpoints, TLS policy, Raft timing and strict reconfiguration settings |
| Executable SHA-256, optional executable, etcd/Go build versions | Run the same bits and validate binary compatibility |
| Container resolver configuration and public peer certificate identity/SANs | Match the DNS/TLS context for peer authentication |
| Membership, local status and local health | Identify current voters, leader, term, progress index and serving state |
| Raw and parsed `etcd_network_active_peers` | Identify the local view of each peer, including stale metric series |
| Client TLS paths and readability | Explain which credentials local probes used or why probes were skipped |

Resolver configuration does not contain DNS record contents. A single report is
a snapshot; it does not establish transport-event ordering or Raft progress over
time. Collect from both serving hosts to compare their views.

## Host requirements and options

Use root on Linux with Bash, Python 3.6+ (standard library only), and `crictl`
access. The shell script embeds its Python implementation and needs no companion
runtime files. `nsenter` and `curl` collect peer metrics; `openssl` reads public
peer certificate metadata. Unavailable checks are recorded.

Runtime access uses the host crictl configuration unless `--runtime-endpoint URL`
is supplied. If multiple etcd containers are running, supply `--container ID` for
the intended cluster. Diagnostics use `crictl exec`; no Kubernetes CLI is used.

Client TLS defaults match HyperShift. Supply `--cacert`, `--cert`, and `--key`
with actual absolute paths inside the selected container when needed. Files stay
on the host. Local probes use HTTPS localhost:2379 and metrics localhost:2382
with certificate verification. Peer certificate metadata comes from the
configured `--peer-cert-file` or `ETCD_PEER_CERT_FILE` path. Run `--help` for options.

## Report and exit status

`schema_version: 2` identifies the format; `collector_version` identifies the
program. The top-level fields are `host`, `process`, `configuration`,
`executable`, `tls`, `checks`, collection timestamps/status, and `artifacts`.
Process/executable identity is verified again after collection to reject mixed
observations from a restart or changed binary.

Successful etcd JSON commands have parsed responses under `checks.*.data` with
full integer precision. Text commands retain `stdout`, `stderr` and `exit_code`.
Peer metrics contain typed `samples` and selected metric lines in `raw`.
Check status can be `ok`, `failed`, `timeout`, `unavailable`, `invalid_json`,
`missing_metric`, or `skipped`.

Exit 0 with `collection_status: "completed"` means collection finished; inspect
individual checks for failures. Exit 2 with `collection_status: "failed"`
indicates a fatal selection, inspection, identity or packaging error. Partial
JSON and, when possible, its archive are retained. Filesystem errors can prevent
artifact creation. Missing Python cannot produce JSON. Help, version and
argument-validation output use normal CLI text.

The collector makes no changes to networking, processes, membership or recovery.
