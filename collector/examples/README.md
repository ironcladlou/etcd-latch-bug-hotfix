# Example collection output

[report.txt](report.txt) is a sanitized, abridged example based on a lab
collection. [command-output.txt](command-output.txt) shows the terminal output.
Names, addresses, container/member/cluster identifiers, and hashes are
illustrative replacements. Software versions describe the lab sample; they are
not prerequisites. The sample includes no executable or archive.

The actual archive contains `report.txt` and `process.json`, plus
`etcd-executable` when `--include-binary` is used. Send back the generated
`.tar.gz` and its `.sha256` file from each serving host. The working directory is
retained locally; it does not need to be sent separately.

The sample shows successful local health/status/membership checks and raw peer
metrics. Its zero-valued metric for remote ID `5555` refers to a removed member:
that ID is absent from the current member list. It does not indicate a failure
of either current peer. Decimal member IDs in etcdctl JSON correspond to the
hexadecimal IDs in metric labels (`8738` = `2222`, `13107` = `3333`, and
`17476` = `4444`). Only the selected local endpoint is health-checked by each
collection; obtain a report from both serving hosts to assess both.

The optional `file` and `getenforce` checks were unavailable in the lab diagnostic
container. Their errors and exit codes demonstrate how failed checks appear.
A generated archive is not a declaration that all checks passed, that the host
supports socket destruction, or that a binary is supported by a repair tool.
No socket destruction is attempted by the collector.
