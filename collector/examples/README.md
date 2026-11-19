# Example JSON output

[report.json](report.json) is a sanitized, abridged example report.
It illustrates both stdout and the `report.json` saved inside the archive:

```sh
sudo bash collect-etcd-host.sh --include-binary > collection.json
```

Send back the archive and checksum whose paths appear under `artifacts` in that
JSON. The archive contains `report.json` and, with `--include-binary`, the
`etcd-executable` file. Process metadata is inside the report. The working
directory is retained locally.

Names, addresses, container/member/cluster identifiers, hashes, and artifact
paths are illustrative replacements. Socket output is shortened. Software
versions are illustrative; they are not prerequisites. No executable or
archive is included in these examples.

Etcd responses are JSON values under `checks.etcd_status.data`,
`checks.etcd_members.data`, and `checks.etcd_health.data`. Peer metrics have both
`checks.active_peers.samples` and `checks.active_peers.raw`.
The zero-valued sample for remote ID `5555` refers to a removed member, absent
from the current member list. It does not indicate a failure of a current peer.
Decimal member IDs in etcdctl JSON correspond to hexadecimal metric labels
(`8738` = `2222`, `13107` = `3333`, `17476` = `4444`).

The unavailable `file` and `getenforce` tools demonstrate per-check errors. The
report still has `collection_status: "completed"`; that describes collection,
not cluster health or repair eligibility. No socket destruction is attempted.
