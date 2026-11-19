# Etcd evidence collection

We need this evidence to reproduce the peer-status problem with the same etcd
bits and configuration, and validate a repair against the exact running binary.
Collect from each reachable, serving etcd member so we can compare their views.

## Using the collector

Run from the host as root, with Python 3 and `crictl` access:

```sh
sudo python3 collect-etcd-host.py
```

The script saves the results and prints the report, archive and checksum paths.
Send the archive and checksum files. The archive contains a JSON report and a **separate etcd
executable**, not binary data embedded in JSON. See the [example](examples/README.md)
for what a report looks like. The executable is required: if copying it fails,
collection fails and no archive is produced. Use `--help` for connection and
certificate options.

## Collecting manually

If the script fails, ordinary text files and command output are fine; you do not
need to recreate its JSON format. Include any partial report and the error.
Label the evidence with the host, Pod/namespace, container ID and UTC collection
time. Use `crictl ps` and `crictl inspect` to identify the intended etcd container
and its current **host PID**.

| Collect | Where to get it / why we need it |
| --- | --- |
| **Running etcd executable and SHA-256** | Copy `/proc/<PID>/exe`, then hash the copy. We need the actual build to validate the memory layout used to identify the intended peer connection. |
| **Image digest and etcd build/version** | Record the image reference/digest from CRI and `etcd --version` from that container. These identify the image, etcd and Go build to reproduce. |
| **Host platform** | `uname -r -m` and OS ID/version from `/etc/os-release`, to match the kernel and architecture. |
| **Etcd configuration** | Relevant process arguments and `ETCD_*` settings: advertised/listening client and peer URLs, TLS verification policy, heartbeat/election timing and strict reconfiguration settings. These establish the behavior to reproduce. |
| **Peer certificate metadata** | Subject, issuer, validity and DNS/IP SANs from the configured peer certificate. For example, `openssl x509 -in /path/to/peer.crt -noout -subject -issuer -dates -ext subjectAltName`. These establish the peer authentication conditions. |
| **Container DNS configuration** | `/proc/<PID>/root/etc/resolv.conf`, to identify the resolver, search domains and options used by etcd. |
| **Current membership, status and health** | Using the existing authenticated local etcdctl connection, collect `member list -w json`, `endpoint status -w json` and `endpoint health -w json`. These identify voters/learners, member IDs, leader, term and serving state. |
| **Raw peer-status metrics** | Retain `etcd_network_active_peers` lines from the local authenticated metrics endpoint, reached from etcd's network namespace. Collect from each serving member to identify asymmetric status and distinguish current members from stale metric series. |
| **Diagnostic connection details** | Record the local client/metrics addresses and CA/client certificate/key **paths**, plus any access errors. These let us reproduce the diagnostic connection without sending credentials. |

To capture the running executable from the host:

```sh
ETCD_PID=12345 # replace with the current etcd host PID
mkdir -p etcd-evidence
cp "/proc/$ETCD_PID/exe" etcd-evidence/etcd-executable
sha256sum etcd-evidence/etcd-executable > etcd-evidence/etcd-executable.sha256
```

Add the remaining evidence as clearly named files, then package it:

```sh
tar -czf etcd-evidence.tar.gz etcd-evidence/
sha256sum etcd-evidence.tar.gz > etcd-evidence.tar.gz.sha256
```

Send both files. Do **not** include private keys, kubeconfigs, pull secrets,
datastore files, or full unfiltered environment/CRI dumps. Certificate metadata
and credential file paths are sufficient. Resolver configuration describes DNS
settings; it does not include the DNS records returned at collection time.
