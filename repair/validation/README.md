# Lab validation evidence

The support catalog in [etcd_peer_repair.py](../etcd_peer_repair.py) references
these lab artifacts by path (relative to `repair/`) and SHA-256. Files are kept
byte-for-byte so the recorded digests can be checked:

```sh
cd repair/validation
sha256sum -c SHA256SUMS
```

The two end-to-end runs are summarized in
[summary.json](validation-refactor/summary.json):

- [Three serving voters](validation-refactor/20261119T014608Z/repair-stdout.json).
- [Two serving voters, third returning during verification](validation-refactor/20261119T014807Z/repair-stdout.json).

Each run includes its collector report, repair audit, independent health
observations, fault events, stream-traffic proof and network cleanup output.
The tested implementation is retained with its exact recorded digest. Changes
to the delivered implementation after those runs affect catalog evidence only.

The degraded run deliberately replaced the third member. Its old-address health
checks fail during that phase; checks of the selected serving pair remain
successful. The archived audits preserve the profile revision observed during
the run. The current catalog points to the repository copies of that evidence.

These are lab outputs with lab identifiers, not customer collections. No etcd
executables, private keys or kubeconfigs are included. Evidence files are for
review and are not required to run the self-contained repair program.
