# Example JSON report

[report.json](report.json) illustrates the report saved in the results directory
and included in the archive. Run:

```sh
sudo python3 collect-etcd-host.py
```

The script prints the saved result locations:

```text
Collection complete.
Report: /var/tmp/etcd-host-report-EXAMPLE1/report.json
Archive: /var/tmp/etcd-host-report-EXAMPLE1.tar.gz
Checksum: /var/tmp/etcd-host-report-EXAMPLE1.tar.gz.sha256
Send the archive and checksum files.
```

Send back the archive and checksum. The archive contains `report.json` and a
separate `etcd-executable` binary file. JSON contains its hash and filename, never its bytes. No executable or
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
