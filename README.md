# Etcd latch bug hotfix

Tools for diagnosing and working around
[etcd-io/etcd#22480](https://github.com/etcd-io/etcd/issues/22480): a peer can
remain marked inactive even while its established streams continue carrying
Raft traffic.

A delayed pipeline failure can mark the peer inactive after its streams have
reconnected. Successful traffic on those streams does not restore the status.
The result is `etcd_network_active_peers=0` despite working replication, which
can cause membership changes to be rejected as an unhealthy cluster and block
automatic recovery.

This repository provides a targeted workaround: identify and close one stream
reader connection so etcd's normal reconnect path marks the peer active again.
It avoids restarting a serving member or changing membership—particularly
useful when only two serving voters remain. It does not patch etcd or fix the
original transport/TLS failure. The proposed upstream fix is
[etcd-io/etcd#22481](https://github.com/etcd-io/etcd/pull/22481).

- [Collect evidence](collector/README.md) to identify the exact bits,
  configuration and peer state.
- [Inspect and repair](repair/README.md) using a validated binary profile,
  live safety checks and a recorded single-connection repair.
