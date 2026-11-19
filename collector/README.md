# Customer host prerequisite collection

Copy `collect-etcd-host.sh` to each of the two serving etcd hosts and run:

```sh
sudo bash collect-etcd-host.sh --include-binary
```

See [example report and terminal output](examples/README.md) for the layout,
failed-check markers, and files to return.

Send back the printed `.tar.gz` and `.sha256` files from each host. The executable
is needed to validate an exact binary profile; omit `--include-binary` if only a
textual report can initially be shared. Reports include internal names and IPs.
No private keys, kubeconfigs, datastore files, complete environment dumps, logs,
or full CRI inspect responses are exported.

Required: Bash, Python 3, crictl, timeout, tar and sha256sum. Optional diagnostic
tools are attempted and their absence recorded. Runtime access uses the host
crictl configuration unless `--runtime-endpoint URL` is supplied. If multiple
etcd containers are running, supply `--container ID` for the intended cluster.

TLS defaults match HyperShift. For other layouts, supply `--cacert`, `--cert`,
and `--key` with absolute paths inside the selected container to credentials
already authorized for etcd diagnostics. These files are used locally, never
exported. Local probes use HTTPS localhost:2379 and metrics localhost:2382;
endpoint differences, authentication failures, missing tools and access denials
are recorded rather than bypassed. Run `--help` for options.

The collector reads process metadata, hashes (and optionally copies) the running
executable, opens `/proc/PID/mem` read-only to check permission without reading
memory, lists peer sockets, and invokes etcd read diagnostics. It does not test
SOCK_DESTROY permissions, close sockets, alter networking, restart processes or
change membership/recovery. A collection failure retains partial files and
prints their location.

Validation: Bash syntax/help checked; the complete collector, including binary
export and archive verification, ran successfully in a temporary privileged
host-PID/network diagnostic Pod on the vivid-pike etcd-1 worker. Membership,
status, health, raw active-peer metrics and the expected executable hash were
present. Optional `file` and `getenforce` commands were unavailable and recorded.
The diagnostic Pod was removed. This validates that access path; the customer's
actual host-shell tooling and permissions remain to be established by their run.
