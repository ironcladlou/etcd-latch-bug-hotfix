# Customer host prerequisite collection

Copy `collect-etcd-host.sh` to each of the two serving etcd hosts and run:

```sh
sudo bash collect-etcd-host.sh --include-binary > collection.json
```

The collector emits a single JSON report on stdout. The identical report is
saved as `report.json` in the generated archive. Send back the archive and checksum
named by `artifacts.archive` and `artifacts.checksum` in the JSON. For example:

```sh
python3 -c 'import json; r=json.load(open("collection.json")); print(r["artifacts"]["archive"]); print(r["artifacts"]["checksum"])'
```

See the [sanitized example](examples/README.md) for the report structure and how
failed checks appear. Reports contain internal names and IPs. No private keys,
kubeconfigs, datastore files, complete environment dumps, logs, or full CRI
inspect responses are exported. The optional executable is needed to validate
an exact binary profile; omit `--include-binary` if initially sharing JSON only.

## Host requirements and options

Run as root on Linux with Bash, Python 3.6+ (standard library only), and access to
`crictl`. The shell entrypoint embeds the Python report builder; there are no
companion runtime files or packages to install. `nsenter`, `ss`, `curl`,
`openssl`, `file` and `getenforce` are attempted as applicable; missing tools and
access failures are recorded. Runtime access uses the host crictl configuration
unless `--runtime-endpoint URL` is supplied. If multiple etcd containers are
running, supply `--container ID` for the intended cluster.

TLS defaults match HyperShift. For other layouts, supply `--cacert`, `--cert`,
and `--key` with absolute paths inside the selected container to credentials
already authorized for etcd diagnostics. These files are used locally, never
exported. Local probes use HTTPS localhost:2379 and metrics localhost:2382;
endpoint differences, authentication failures, missing tools and access denials
are recorded rather than bypassed. Run `--help` for options.

## JSON format and exit status

`schema_version: 1` identifies the JSON format; `collector_version` identifies
the program. The report contains:

- `host`: kernel, architecture, OS, Python and OpenSSL information.
- `process`: allowlisted container/process metadata, settings and memory-open
  permission result. No process memory is read.
- `executable`: SHA-256, inode and optional exported filename. Hashing and copying
  use the same open executable file.
- `tls`: container credential paths and readability results; no credential contents.
- `checks`: named diagnostic results. Successful etcd JSON commands have `data`
  containing their parsed response, retaining full integer precision. Other
  commands retain `stdout` and `stderr` separately with `exit_code` and `status`.
  Active-peer results contain typed `samples` and selected metric lines in `raw`;
  unrelated metrics are excluded. Checks may be `ok`, `failed`, `timeout`,
  `unavailable`, `invalid_json`, `missing_metric`, or `skipped`.
- `artifacts`: paths to the report, archive, checksum and retained working directory.

Exit 0 and `collection_status: "completed"` mean collection completed, including
when optional checks failed. They do **not** mean all checks passed, all members
are healthy, or a binary is supported by a repair tool. Review individual checks.
Exit 2 and `collection_status: "failed"` indicate a fatal selection, inspection,
identity or packaging error. Partial JSON and, when possible, its archive are
retained. Permission/output-directory errors may prevent creating artifacts;
bootstrap errors such as a missing Python interpreter cannot produce JSON.
`--help`, `--version` and argument-validation errors use normal CLI text.

The collector checks process/executable identity again after collection. It does
not test SOCK_DESTROY permissions, close sockets, alter networking, restart
processes or change membership/recovery. Only the selected local endpoint is
health-checked; collect from both serving hosts to assess both.
