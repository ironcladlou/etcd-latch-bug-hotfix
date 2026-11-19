# Example JSON report

[report.json](report.json) illustrates both stdout and the `report.json` inside
the archive:

```sh
sudo bash collect-etcd-host.sh --include-binary > collection.json
```

Send back the archive and checksum named under `artifacts`. The archive contains
`report.json` and, with `--include-binary`, a separate `etcd-executable` binary
file. JSON contains its hash and filename, never its bytes. No executable or
archive is included in this example.

Identities, addresses, hashes, certificate metadata, resolver settings and
artifact paths are illustrative placeholders. Software versions describe an
example build; they are not requirements.

Etcd responses appear under `checks.etcd_status.data`,
`checks.etcd_members.data`, and `checks.etcd_health.data`. Peer metrics have both
`checks.active_peers.samples` and `checks.active_peers.raw`. Configuration is
under `configuration.env` and `configuration.flags`.

The zero-valued metric for remote ID `5555` refers to a removed member, absent
from the member list. Decimal member IDs in etcdctl JSON correspond to hexadecimal
metric labels (`8738` = `2222`, `13107` = `3333`, `17476` = `4444`). Match metrics
to current membership before interpreting a zero as a current peer failure.

Per-check errors have a status and diagnostic error or stderr, for example:

```json
{"status": "unavailable", "exit_code": null, "error": "[Errno 2] No such file or directory: 'openssl'"}
```

A report can have `collection_status: "completed"` while individual checks fail.
That status describes collection, not cluster health or repair eligibility.
