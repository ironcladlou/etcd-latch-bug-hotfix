#!/usr/bin/env python3
"""Inspect or reconnect ONE identified etcd stream reader. Python 3.6+ / Linux.

No package installation, debugger attachment, process writes, eBPF or firewall
rules. Uses crictl and nsenter. Socket destruction is cookie-qualified
INET_DIAG/SOCK_DESTROY, the kernel interface used by ss -K.
"""
import argparse
import concurrent.futures
import datetime
import hashlib
import http.client
import ipaddress
import json
import os
import pathlib
import platform
import re
import secrets
import shutil
import socket
import ssl
import struct
import subprocess
import sys
import time
import urllib.parse

VERSION = "0.3.0"
# Compatibility rules are immutable inputs, separate from deployment defaults
# and live safety policy. A collection never adds itself to this trusted catalog.
SUPPORT_CATALOG = (
    {
        "id": "openshift-etcd-3.5.26-amd64",
        "revision": 3,
        "compatibility": {
            "executable_sha256": "9fd1e8e4f0577c14b18d665f1d4403390c50dd1f8b1eead09754ee4f1727ea66",
            "architecture": "x86_64"
        },
        "reader": {
            "pointer_format": "<q",
            "sysfd_offset": 16,
            "reader_symbol": "rafthttp.(*streamReader).decodeLoop(",
            "decoder_symbol": "rafthttp.(*msgAppV2Decoder).decode",
            "fd_pattern": "internal/poll\\.\\(\\*FD\\)\\.Read\\((0x[0-9a-f]+),"
        },
        "validation": {
            "result": "live single-reader repair verified",
            "evidence": [
                {
                    "artifact": "validation/lab-repair-stdout.json",
                    "sha256": "330a9ed48d0f43e4eb7ac47d81b46ad586639fef2a0366fff8afe224360e696a"
                },
                {
                    "artifact": "validation/lab-health-monitor-summary.json",
                    "sha256": "2ef953b72f12fe7f56e4c46ebd5af088d5e003d3c1053aea215141eb336d94f7"
                },
                {
                    "artifact": "validation/lab-platform.txt",
                    "sha256": "5aaf8e7d23f83aef30f8ac4612c86075c2af7712862f1789191a623cb8cfb5eb"
                }
            ],
            "tested_context": {
                "etcd_version": "3.5.26",
                "openshift_version": "4.20.23",
                "healthy_voters": 3,
                "voters": 3,
                "kernel": "5.14.0-687.44.1.el9_8.x86_64"
            },
            "coverage_notes": [
                "Live end-to-end collection, exported-binary assessment, reproduction, single-reader repair, and no-op follow-up passed with three and two serving voters.",
                "The two-voter run used a normal third-member Pod replacement; persistent third-member failure and every possible recovery transition are not claimed as tested."
            ],
            "match_policy": "Only executable hash and architecture are compatibility gates. Context is evidence, not an exact-environment requirement.",
            "runs": [
                {
                    "scenario": "three serving voters",
                    "collection_sha256": "d46976369b21f9987fa27f99a84ebabd76c873ce363d59143b2bc64d6c51b040",
                    "tested_script_sha256": "abd3c0bacfea97f542cbf11e4061da2c8e15062c156687db023f2f5392ad6463",
                    "repair_audit": {
                        "artifact": "validation/validation-refactor/20261119T014608Z/repair-stdout.json",
                        "sha256": "5420ba5d6c518bbcd4dc17067e7ccc275944f18afd08c81e3213196a06979f67"
                    },
                    "healthy_voters_before": 3,
                    "socket_closes": 1,
                    "outcome": "reconnected_and_verified",
                    "collection_artifact": "validation/validation-refactor/20261119T014608Z/collection.json",
                    "tested_script_artifact": "validation/validation-refactor/implementation-tested.py",
                    "health_observations": {
                        "artifact": "validation/validation-refactor/20261119T014608Z/repair-health.jsonl",
                        "sha256": "5d19975b0867ad34f168cf7c7805e82272031d15a0a4622a453b7a1a73828e8a"
                    }
                },
                {
                    "scenario": "two serving voters; third rejoins during verification",
                    "collection_sha256": "30076735d872bf5ad5bd4ea77f81f4ac4c6d33cc82bf6733fab173f1b1534347",
                    "tested_script_sha256": "abd3c0bacfea97f542cbf11e4061da2c8e15062c156687db023f2f5392ad6463",
                    "repair_audit": {
                        "artifact": "validation/validation-refactor/20261119T014807Z/repair-stdout.json",
                        "sha256": "bef6d9eb4b00f8eddaee74056f634d169d03348f7c9c33ecb870b0ba22bbb76c"
                    },
                    "healthy_voters_before": 2,
                    "socket_closes": 1,
                    "outcome": "reconnected_and_verified",
                    "collection_artifact": "validation/validation-refactor/20261119T014807Z/collection.json",
                    "tested_script_artifact": "validation/validation-refactor/implementation-tested.py",
                    "health_observations": {
                        "artifact": "validation/validation-refactor/20261119T014807Z/repair-health.jsonl",
                        "sha256": "d174b007523bab1247cbcff62a8d9abe164ccf5942e27eed7560b8941b94b2e2"
                    }
                }
            ]
        }
    },
)
DEPLOYMENT_DEFAULTS = {
    "ca": "/etc/etcd/tls/etcd-ca/ca.crt",
    "cert": "/etc/etcd/tls/client/etcd-client.crt",
    "key": "/etc/etcd/tls/client/etcd-client.key",
    "client_port": 2379, "metrics_port": 2382,
}



class Refusal(Exception):
    pass


def require(condition, message):
    if not condition:
        raise Refusal(message)


def now():
    return datetime.datetime.now(datetime.timezone.utc).isoformat()


def run(args, data=None, timeout=15):
    p = subprocess.run(args, input=data, stdout=subprocess.PIPE,
                       stderr=subprocess.PIPE, universal_newlines=True,
                       timeout=timeout)
    if p.returncode:
        raise Refusal("command failed: {}: {}".format(
            pathlib.Path(args[0]).name, p.stderr.strip()[:1500]))
    return p.stdout


def proc_start(pid):
    # comm may contain spaces and parentheses. Field 22 starts after the last ).
    text = pathlib.Path("/proc/{}/stat".format(pid)).read_text()
    return text[text.rfind(")") + 2:].split()[19]


def identity(pid):
    return {"pid": pid, "start_ticks": proc_start(pid),
            "exe_inode": os.stat("/proc/{}/exe".format(pid)).st_ino,
            "netns_inode": os.stat("/proc/{}/ns/net".format(pid)).st_ino}


def exe_hash(pid):
    h = hashlib.sha256()
    with open("/proc/{}/exe".format(pid), "rb") as f:
        for block in iter(lambda: f.read(1024 * 1024), b""):
            h.update(block)
    return h.hexdigest()


# Discovery: collect facts without deciding whether they are supported.
def discover_container(args):
    """Resolve one running container so later decisions cannot target its neighbor."""
    cri = [args.crictl, "--runtime-endpoint", args.runtime_endpoint]
    data = json.loads(run(cri + ["ps", "--label",
        "io.kubernetes.pod.namespace=" + args.namespace, "--label",
        "io.kubernetes.pod.name=" + args.pod, "--name", "^etcd$", "-o", "json"]))
    containers = [c for c in data.get("containers", [])
                  if c.get("metadata", {}).get("name") == "etcd"
                  and c.get("labels", {}).get("io.kubernetes.pod.namespace") == args.namespace
                  and c.get("labels", {}).get("io.kubernetes.pod.name") == args.pod]
    require(len(containers) == 1, "expected exactly one selected running etcd container")
    cid = containers[0]["id"]
    detail = json.loads(run(cri + ["inspect", cid]))
    info = detail.get("info", {})
    if isinstance(info, str):
        info = json.loads(info)
    pid = int(info.get("pid", 0))
    require(pid > 1, "CRI did not supply a valid host PID")
    return {"container_id": cid, "pid": pid,
            "image_ref": detail.get("status", {}).get("imageRef")}


def read_settings(pid):
    """Normalize supported env/flag settings; flags win without copying secrets."""
    keys = {"advertise-client-urls", "listen-client-urls", "listen-peer-urls", "listen-metrics-urls", "name"}
    settings = {}
    for item in pathlib.Path("/proc/{}/environ".format(pid)).read_bytes().split(b"\0"):
        key, sep, value = item.partition(b"=")
        key = key.decode("utf-8", "replace")
        option = key[5:].lower().replace("_", "-") if key.startswith("ETCD_") else ""
        if sep and option in keys:
            settings[option] = value.decode()
    argv = pathlib.Path("/proc/{}/cmdline".format(pid)).read_bytes().decode().split("\0")
    for i, arg in enumerate(argv):
        key, sep, value = arg[2:].partition("=") if arg.startswith("--") else ("", "", "")
        if key in keys:
            settings[key] = value if sep else (argv[i+1] if i+1 < len(argv) else "")
    return settings


def discover(args):
    """Observe live identities and settings; never trust a saved collection as live truth."""
    container = discover_container(args)
    pid = container["pid"]
    before = identity(pid)
    require(pathlib.Path("/proc/{}/comm".format(pid)).read_text().strip() == "etcd",
            "selected process is not etcd")
    facts = {"executable_sha256": exe_hash(pid), "architecture": platform.machine(),
             "image_ref": container["image_ref"], "kernel_release": platform.release()}
    settings = read_settings(pid)
    require(identity(pid) == before, "process changed during discovery")
    return {"container_id": container["container_id"], "process": before,
            "facts": facts, "settings": settings}


# Support: pure matching against narrow binary compatibility requirements.
def profile_digest(profile):
    """Pin the reviewed profile, including its validation evidence, in every audit."""
    return hashlib.sha256(json.dumps(profile, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def normalized_architecture(value):
    return {"amd64": "x86_64"}.get(value, value)


def assess_support(facts, catalog=SUPPORT_CATALOG):
    """Match necessary compatibility properties, not incidental image/host identities."""
    candidates = []
    for profile in catalog:
        checks = []
        for key, expected in profile["compatibility"].items():
            observed = facts.get(key)
            if key == "architecture":
                observed = normalized_architecture(observed)
            checks.append({"property": key, "expected": expected, "observed": observed,
                           "matched": expected == observed})
        candidates.append({"profile_id": profile["id"], "revision": profile["revision"],
                           "profile_sha256": profile_digest(profile), "checks": checks,
                           "matched": all(c["matched"] for c in checks)})
    matched = [c for c in candidates if c["matched"]]
    selected = matched[0] if len(matched) == 1 else None
    return {"supported": selected is not None, "selected": selected, "candidates": candidates,
            "reason": "unique validated binary profile" if selected else
                      "no unique validated binary profile", "observed_facts": dict(facts)}


def supported_profile(assessment, catalog=SUPPORT_CATALOG):
    """Only a unique trusted match may authorize reading a Go object layout."""
    require(assessment["supported"], assessment["reason"])
    selected = assessment["selected"]
    return next(p for p in catalog if p["id"] == selected["profile_id"]
                and profile_digest(p) == selected["profile_sha256"])


def collection_facts(collection):
    """Use a collection for offline compatibility assessment, never repair eligibility."""
    digest = collection["executable"]["sha256"]
    require(re.fullmatch(r"[0-9a-f]{64}", digest), "invalid collected executable SHA256")
    return {"executable_sha256": digest, "architecture": collection["host"]["architecture"],
            "kernel_release": collection["host"].get("kernel_release"),
            "image_ref": collection.get("process", {}).get("image_ref")}


# Configuration: deployment choices are independent of the executable profile.
def diagnostic_config(args, target):
    """Resolve TLS paths/endpoints without requiring the lab's names, addresses or image."""
    settings, pid = target["settings"], target["process"]["pid"]
    urls = [urllib.parse.urlsplit(u) for u in settings.get("advertise-client-urls", "").split(",") if u]
    advertised = next((u for u in urls if u.scheme == "https" and u.hostname), None)
    host = args.server_name or (advertised.hostname if advertised else None)
    require(host, "supply --server-name or configure an HTTPS advertised client URL")
    root = "/proc/{}/root".format(pid)
    cfg = {"pid": pid, "server_name": host,
           "client_port": args.client_port or ((advertised.port or 443) if advertised else DEPLOYMENT_DEFAULTS["client_port"]),
           "metrics_port": args.metrics_port or DEPLOYMENT_DEFAULTS["metrics_port"],
           "resolv": root + "/etc/resolv.conf", "hosts": root + "/etc/hosts"}
    for key in ["ca", "cert", "key"]:
        path = getattr(args, key) or DEPLOYMENT_DEFAULTS[key]
        require(path.startswith("/") and ".." not in pathlib.PurePosixPath(path).parts,
                "TLS paths must be absolute container paths")
        cfg[key] = root + path
        require(os.path.isfile(cfg[key]), "missing mounted TLS {} file".format(key))
    return cfg


def prepare_target(args):
    """Compose observations and configuration; support remains an explicit decision."""
    target = discover(args)
    target["support"] = assess_support(target["facts"])
    target["config"] = diagnostic_config(args, target)
    return target


def dns_name(packet, offset):
    labels, seen, end = [], set(), None
    while True:
        require(0 <= offset < len(packet) and offset not in seen, "invalid DNS name")
        seen.add(offset)
        n = packet[offset]
        if n & 0xc0 == 0xc0:
            require(offset + 1 < len(packet), "truncated DNS pointer")
            if end is None:
                end = offset + 2
            offset = ((n & 0x3f) << 8) | packet[offset + 1]
            continue
        require(n <= 63 and offset + n + 1 <= len(packet), "invalid DNS label")
        offset += 1
        if not n:
            return ".".join(labels), end or offset
        labels.append(packet[offset:offset+n].decode("ascii"))
        offset += n


def dns_answers(packet, qid):
    require(len(packet) >= 12, "short DNS response")
    ident, flags, qn, an, _, _ = struct.unpack("!6H", packet[:12])
    require(ident == qid and flags & 0x8000 and not flags & 0x0200,
            "mismatched or truncated DNS response")
    if flags & 15:
        return []
    off, addresses = 12, []
    for _ in range(qn):
        _, off = dns_name(packet, off)
        off += 4
    for _ in range(an):
        _, off = dns_name(packet, off)
        require(off + 10 <= len(packet), "short DNS record")
        typ, cls, _, n = struct.unpack("!HHIH", packet[off:off+10])
        off += 10
        require(off + n <= len(packet), "truncated DNS record")
        if typ == 1 and cls == 1 and n == 4:
            addresses.append(socket.inet_ntoa(packet[off:off+n]))
        off += n
    return sorted(set(addresses))


def resolve(host, cfg):
    try:
        require(ipaddress.ip_address(host).version == 4, "IPv6 is not validated")
        return [host]
    except ValueError:
        pass
    for line in pathlib.Path(cfg["hosts"]).read_text().splitlines():
        fields = line.split("#", 1)[0].split()
        if len(fields) > 1 and host in fields[1:]:
            try:
                if ipaddress.ip_address(fields[0]).version == 4:
                    return [fields[0]]
            except ValueError:
                pass
    nameservers, search = [], []
    for line in pathlib.Path(cfg["resolv"]).read_text().splitlines():
        fields = line.split("#", 1)[0].split()
        if len(fields) > 1 and fields[0] == "nameserver":
            if ipaddress.ip_address(fields[1]).version == 4:
                nameservers.append(fields[1])
        if fields and fields[0] == "search":
            search = fields[1:]
    require(nameservers, "no IPv4 Pod DNS nameserver found")
    candidates = [host.rstrip(".")]
    if not host.endswith("."):
        candidates += [host + "." + suffix for suffix in search]
    for name in candidates:
        wire = b"".join(bytes([len(x)]) + x.encode("ascii") for x in name.split(".")) + b"\0"
        for ns in nameservers[:2]:
            qid = secrets.randbelow(65536)
            query = struct.pack("!6H", qid, 0x100, 1, 0, 0, 0) + wire + struct.pack("!HH", 1, 1)
            try:
                with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
                    s.settimeout(1.0)
                    s.connect((ns, 53))
                    s.send(query)
                    result = dns_answers(s.recv(65535), qid)
                    if result:
                        return result
            except (OSError, Refusal):
                continue
    raise Refusal("cannot resolve selected member hostname " + host)


def request(cfg, host, port, path, ip=None, body=None):
    context = ssl.create_default_context(cafile=cfg["ca"])
    context.load_cert_chain(cfg["cert"], cfg["key"])
    ips = [ip] if ip else resolve(host, cfg)
    require(len(ips) == 1, "member hostname must resolve to exactly one IPv4 address")
    connection = http.client.HTTPSConnection(host, port, context=context, timeout=3)
    try:
        connection.sock = context.wrap_socket(
            socket.create_connection((ips[0], port), timeout=3), server_hostname=host)
        connection.request("POST" if body is not None else "GET", path,
                           body=json.dumps(body) if body is not None else None,
                           headers={"Content-Type": "application/json"} if body is not None else {})
        response = connection.getresponse()
        data = response.read(16 * 1024 * 1024 + 1)
        require(len(data) <= 16 * 1024 * 1024, "oversize diagnostic response")
        require(response.status == 200, "diagnostic HTTP {} for {}".format(response.status, path))
        return data.decode("utf-8")
    finally:
        connection.close()


def metrics(text):
    active = {}
    for line in text.splitlines():
        m = re.fullmatch(r'etcd_network_active_peers\{([^}]+)\}\s+([01](?:\.0)?)', line)
        if m:
            labels = dict(re.findall(r'(\w+)="([^"]*)"', m.group(1)))
            active[(labels.get("Local"), labels.get("Remote"))] = int(float(m.group(2)))
    return active


def validate_member_status(status, member_id, cluster, leader, term):
    """A reachable endpoint counts only for the claimed member and current consensus."""
    require(int(status["header"]["cluster_id"]) == cluster, "member cluster mismatch")
    require(int(status["header"]["member_id"]) == member_id, "member identity mismatch")
    require(not status.get("errors"), "etcd status reports errors")
    require(int(status["leader"]) == leader and int(status["raftTerm"]) == term,
            "member does not agree with local leader and term")
    require(int(status["raftAppliedIndex"]) >= 0, "invalid applied index")


def probe_member(member, cfg, cluster, leader, term):
    """Try advertised IPv4 client endpoints; one failed address must not hide a serving voter."""
    result = {"id": format(int(member["ID"]), "x"), "name": member.get("name"),
              "is_learner": bool(member.get("isLearner", False)), "healthy": False,
              "peer_urls": member.get("peerURLs", []), "probe_errors": []}
    for value in member.get("clientURLs", []):
        try:
            url = urllib.parse.urlsplit(value)
            require(url.scheme == "https" and url.hostname, "member client URL must be HTTPS")
            addresses = resolve(url.hostname, cfg)
        except (Refusal, OSError, ValueError) as error:
            result["probe_errors"].append(str(error))
            continue
        for address in addresses:
            try:
                health = json.loads(request(cfg, url.hostname, url.port or 443, "/health", address))
                require(health.get("health") in [True, "true"], "member health check failed")
                status = json.loads(request(cfg, url.hostname, url.port or 443,
                                            "/v3/maintenance/status", address, {}))
                validate_member_status(status, int(member["ID"]), cluster, leader, term)
                return dict(result, healthy=True, ip=address, status=status)
            except (Refusal, OSError, ValueError, KeyError, TypeError, http.client.HTTPException) as error:
                result["probe_errors"].append(str(error))
    result["probe_error"] = "; ".join(result["probe_errors"]) or "member has no advertised client URL"
    return result


def quorum_view(members):
    voters = {m["id"] for m in members if not m["is_learner"]}
    healthy = {m["id"] for m in members if m["healthy"] and not m["is_learner"]}
    required = len(voters) // 2 + 1
    return {"voter_ids": sorted(voters), "healthy_voter_ids": sorted(healthy),
            "required": required, "available": len(healthy) >= required}


def snapshot(cfg):
    host, port = cfg["server_name"], cfg["client_port"]
    local = json.loads(request(cfg, host, port, "/v3/maintenance/status", "127.0.0.1", {}))
    ml = json.loads(request(cfg, host, port, "/v3/cluster/member/list", "127.0.0.1", {}))
    members = ml.get("members", [])
    require(members and len({int(m["ID"]) for m in members}) == len(members),
            "empty or duplicate membership")
    cluster = int(local["header"]["cluster_id"])
    local_id = int(local["header"]["member_id"])
    leader, term = int(local["leader"]), int(local["raftTerm"])
    require(leader != 0 and not local.get("errors"), "local status has no leader or reports errors")
    require(int(ml["header"]["cluster_id"]) == cluster, "inconsistent cluster identities")
    with concurrent.futures.ThreadPoolExecutor(max_workers=min(len(members), 8)) as pool:
        serving = list(pool.map(lambda m: probe_member(m, cfg, cluster, leader, term), members))
    text = request(cfg, host, cfg["metrics_port"], "/metrics", "127.0.0.1")
    local_hex = format(local_id, "x")
    active = {remote: value for (loc, remote), value in metrics(text).items() if loc == local_hex}
    return {"time": now(), "cluster_id": format(cluster, "x"), "member_id": local_hex,
            "members": serving, "active_peers": active, "quorum": quorum_view(serving),
            "leader": format(leader, "x"), "term": term}


# Linux SOCK_DIAG_BY_FAMILY / SOCK_DESTROY. The 64-bit cookie is checked by
# the kernel atomically with the tuple, unlike a separate ss lookup + ss -K.
def diag_request(msg_type, family=socket.AF_INET, local=None, remote=None,
                 cookie=(0xffffffff, 0xffffffff), dump=False):
    require(family == socket.AF_INET, "only IPv4 socket diagnostics are validated")
    lp, rp = (local[1], remote[1]) if local and remote else (0, 0)
    la = socket.inet_aton(local[0]) if local else b"\0" * 4
    ra = socket.inet_aton(remote[0]) if remote else b"\0" * 4
    sid = struct.pack("!HH", lp, rp) + la + b"\0" * 12 + ra + b"\0" * 12
    sid += struct.pack("=III", 0, *cookie)
    payload = struct.pack("=BBBBI", family, socket.IPPROTO_TCP, 0, 0, 2) + sid
    seq = secrets.randbelow(0x7ffffffe) + 1
    flags = 1 | (0x300 if dump else 4)  # REQUEST + DUMP or ACK
    header = struct.pack("=IHHII", 16 + len(payload), msg_type, flags, seq, 0)
    records = []
    with socket.socket(socket.AF_NETLINK, socket.SOCK_RAW, 4) as s:
        s.bind((0, 0))
        s.settimeout(3)
        s.sendto(header + payload, (0, 0))
        while True:
            packet = s.recv(1024 * 1024)
            off = 0
            while off + 16 <= len(packet):
                size, typ, _, rseq, _ = struct.unpack_from("=IHHII", packet, off)
                require(size >= 16 and off + size <= len(packet), "invalid socket diagnostic message")
                data = packet[off+16:off+size]
                off += (size + 3) & ~3
                if rseq != seq:
                    continue
                if typ == 2:
                    code = struct.unpack_from("=i", data)[0]
                    if code:
                        raise Refusal("socket diagnostic error: " + os.strerror(-code))
                    return records
                if typ == 3:
                    return records
                if typ == 20 and len(data) >= 72:
                    family, state = data[0], data[1]
                    if family != socket.AF_INET:
                        continue
                    lp, rp = struct.unpack_from("!HH", data, 4)
                    records.append({"local_ip": socket.inet_ntoa(data[8:12]),
                        "local_port": lp, "remote_ip": socket.inet_ntoa(data[24:28]),
                        "remote_port": rp, "cookie": list(struct.unpack_from("=II", data, 44)),
                        "inode": struct.unpack_from("=I", data, 68)[0], "state": state})


def netop(req):
    cfg, action = req["config"], req["action"]
    if "process" in req:
        require(identity(cfg["pid"]) == req["process"], "namespace child process identity mismatch")
        require(os.stat("/proc/self/ns/net").st_ino == req["process"]["netns_inode"],
                "namespace child entered a different network namespace")
    if action == "peer_endpoints":
        endpoints = []
        for value in req["urls"]:
            url = urllib.parse.urlsplit(value)
            require(url.scheme == "https" and url.hostname, "peer endpoint must use HTTPS")
            endpoints.extend({"ip": ip, "port": url.port or 443} for ip in resolve(url.hostname, cfg))
        require(endpoints, "no advertised IPv4 peer endpoints")
        return {"endpoints": endpoints}
    if action == "snapshot":
        return snapshot(cfg)
    if action == "goroutines":
        return {"text": request(cfg, cfg["server_name"], cfg["client_port"],
                                "/debug/pprof/goroutine?debug=2", "127.0.0.1")}
    if action == "sockets":
        return {"sockets": diag_request(20, dump=True)}
    if action == "destroy":
        target = req["socket"]
        require(target["cookie"] != [0xffffffff, 0xffffffff], "missing socket cookie")
        require(target in diag_request(20, dump=True), "selected socket has changed")
        diag_request(21, local=(target["local_ip"], target["local_port"]),
                     remote=(target["remote_ip"], target["remote_port"]),
                     cookie=tuple(target["cookie"]))
        return {"destroyed": target, "time": now()}
    raise Refusal("invalid namespace operation")


def network(args, target, action, **kw):
    req = {"action": action, "config": target["config"], "process": target["process"]}
    req.update(kw)
    text = run([args.nsenter, "-t", str(target["process"]["pid"]), "-n", "--",
                sys.executable, os.path.abspath(__file__), "_netop"],
               json.dumps(req), timeout=35)
    return json.loads(text)


def stack_readers(text, reader_profile=None):
    """Parse only exact, non-optimized pointers from the validated stack format."""
    reader_profile = reader_profile or SUPPORT_CATALOG[0]["reader"]
    readers = []
    for block in text.split("\n\n"):
        if reader_profile["reader_symbol"] not in block:
            continue
        kind = "msgappv2" if reader_profile["decoder_symbol"] in block else "message"
        # Optimized '?' pointer values are deliberately not accepted.
        f = re.search(reader_profile["fd_pattern"], block)
        if f:
            readers.append({"poll_fd_pointer": int(f.group(1), 16), "kind": kind,
                            "goroutine": block.splitlines()[0]})
    return readers


def choose_reader(readers, sockets, peer_ip, fd_info, peer_endpoints=None):
    """Join stack/FD/inode/cookie evidence without inferring a role from ports alone."""
    endpoints = {(e["ip"], e["port"]) for e in peer_endpoints} if peer_endpoints else {(peer_ip, 2380)}
    candidates = []
    for reader in readers:
        if reader["kind"] != "msgappv2":
            continue
        info = fd_info(reader["poll_fd_pointer"])
        if info is None:
            continue
        fd, inode = info
        matches = [s for s in sockets if s["inode"] == inode and s["state"] == 1
                   and (s["remote_ip"], s["remote_port"]) in endpoints
                   and s["local_port"] != s["remote_port"]]
        if len(matches) == 1:
            candidates.append(dict(reader, fd=fd, socket=matches[0]))
    unique = {tuple(c["socket"]["cookie"]): c for c in candidates}
    require(len(unique) == 1, "cannot unambiguously identify one outbound MsgApp v2 reader")
    return list(unique.values())[0]


def read_fd_info(pid, pointer, reader_profile):
    """Read one validated Sysfd field; cross-check its live /proc socket inode."""
    try:
        with open("/proc/{}/mem".format(pid), "rb", buffering=0) as memory:
            size = struct.calcsize(reader_profile["pointer_format"])
            value = os.pread(memory.fileno(), size, pointer + reader_profile["sysfd_offset"])
            fd = struct.unpack(reader_profile["pointer_format"], value)[0]
        if not 0 <= fd <= 1000000:
            return None
        link = os.readlink("/proc/{}/fd/{}".format(pid, fd))
        match = re.fullmatch(r"socket:\[(\d+)\]", link)
        return (fd, int(match.group(1))) if match else None
    except (OSError, struct.error, ValueError):
        return None


def select(args, target, snap):
    """Identify exactly one working reader; no saved tuple or process address is trusted."""
    profile = supported_profile(target["support"])
    peer = next((m for m in snap["members"] if m["id"] == args.peer_id), None)
    require(peer is not None and peer["id"] != snap["member_id"], "target must be another current voter")
    endpoints = network(args, target, "peer_endpoints", urls=peer["peer_urls"])["endpoints"]
    for attempt in range(3):
        text = network(args, target, "goroutines")["text"]
        sockets = network(args, target, "sockets")["sockets"]
        readers = stack_readers(text, profile["reader"])
        fd_info = {r["poll_fd_pointer"]: read_fd_info(target["process"]["pid"], r["poll_fd_pointer"], profile["reader"])
                   for r in readers}
        try:
            result = choose_reader(readers, sockets, peer["ip"], fd_info.get, endpoints)
            return dict(result, peer_id=peer["id"], peer_ip=result["socket"]["remote_ip"])
        except Refusal:
            if attempt == 2:
                raise
        time.sleep(.2)


def membership_signature(snap):
    return {(m["id"], m["is_learner"]) for m in snap["members"]}


# Eligibility and verification policies: pure decisions over observed inputs.
def assess_eligibility(snap, args, baseline=None, after_close=False):
    """Gate live risk, not tested topology: two serving voters out of three qualify."""
    checks = []
    def check(name, passed, reason):
        checks.append({"check": name, "passed": bool(passed), "reason": reason})
    check("expected_cluster", not args.expect_cluster_id or snap.get("cluster_id") == args.expect_cluster_id,
          "expected cluster ID mismatch")
    check("expected_member", not args.expect_member_id or snap.get("member_id") == args.expect_member_id,
          "expected local member ID mismatch")
    quorum = quorum_view(snap.get("members", []))
    check("voting_quorum", quorum["available"], "healthy voting quorum is unavailable")
    check("distinct_peer", args.peer_id != snap.get("member_id"), "selected peer must be another voter")
    check("selected_pair", {snap.get("member_id"), args.peer_id} <= set(quorum["healthy_voter_ids"]),
          "local and selected peer must both be healthy current voters")
    if baseline:
        check("stable_identity", snap.get("cluster_id") == baseline["cluster_id"] and
              snap.get("member_id") == baseline["member_id"], "cluster/process identity changed")
        if not after_close:
            check("fresh_membership", membership_signature(snap) == membership_signature(baseline),
                  "membership or voting roles changed before close")
    # Consensus is checked within each snapshot. A normal election between
    # snapshots is not a reason to declare a compatible installation unsupported.
    return {"eligible": all(c["passed"] for c in checks), "quorum": quorum, "checks": checks}


def require_eligible(assessment):
    """Keep refusal reporting separate from the policy that explains the decision."""
    require(assessment["eligible"], "; ".join(c["reason"] for c in assessment["checks"] if not c["passed"]))


def verify_snapshot(snap, args, baseline=None, after_close=False):
    """Apply live eligibility without mixing it with binary compatibility."""
    require_eligible(assess_eligibility(snap, args, baseline, after_close))


def assess_failure(snap, peer_id):
    """A current inactive gauge is applicable only after serving-pair eligibility succeeds."""
    value = snap["active_peers"].get(peer_id)
    return {"applicable": value == 0, "already_active": value == 1,
            "metric": value, "reason": "inactive current peer" if value == 0 else
                                      "peer already active" if value == 1 else "current-peer metric absent"}


def progress_state(snap, first_indexes, peer_id):
    """Return new index baselines; failed voters need not advance and learners do not count."""
    indexes, advanced = dict(first_indexes), set()
    for member in snap["members"]:
        if not member["healthy"]:
            continue
        index = int(member["status"]["raftAppliedIndex"])
        original = indexes.setdefault(member["id"], index)
        if not member["is_learner"] and index > original:
            advanced.add(member["id"])
    progressed = ({snap["member_id"], peer_id} <= advanced and
                  len(advanced) >= quorum_view(snap["members"])["required"])
    return {"indexes": indexes, "progressed": progressed, "advanced_voter_ids": sorted(advanced)}


def advancing_quorum(snap, first_indexes, peer_id):
    return progress_state(snap, first_indexes, peer_id)["progressed"]


def verification_step(state, snap, args, baseline, elapsed):
    """Require a stable, serving window; reset it for elections or transient probe failures."""
    eligibility = assess_eligibility(snap, args, baseline, after_close=True)
    progress = progress_state(snap, state["indexes"], args.peer_id)
    anchor = [snap["leader"], snap["term"]]
    active = eligibility["eligible"] and snap["active_peers"].get(args.peer_id) == 1
    since = state["stable_since"] if state.get("anchor") == anchor else None
    since = (elapsed if since is None else since) if active else None
    return {"indexes": progress["indexes"], "stable_since": since, "anchor": anchor,
            "eligibility": eligibility, "progress": progress,
            "complete": since is not None and elapsed - since >= args.stable_seconds and progress["progressed"]}


# Audit I/O is explicit; no nested callback owns mutable report state.
def open_audit(path):
    """Refuse reuse of an audit filename, so a prior close cannot be hidden."""
    return os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600) if path else None


def write_audit(fd, report):
    """Persist intent before the only mutation; handle partial writes and fsync."""
    if fd is None:
        return
    data = (json.dumps(report, indent=2) + "\n").encode()
    os.lseek(fd, 0, os.SEEK_SET)
    remaining = memoryview(data)
    while remaining:
        count = os.write(fd, remaining)
        require(count > 0, "audit write made no progress")
        remaining = remaining[count:]
    os.ftruncate(fd, len(data))
    os.fsync(fd)


def audit_target(target):
    """Include facts and support decisions; mounted private-key contents never enter a report."""
    return {key: value for key, value in target.items() if key != "config"}


def revalidate_plan(args, target, baseline, candidate):
    """Resolve the plan again immediately before close, with the same process/profile/socket."""
    fresh = prepare_target(args)
    require(fresh["process"] == target["process"] and fresh["container_id"] == target["container_id"]
            and fresh["facts"]["executable_sha256"] == target["facts"]["executable_sha256"],
            "container or executable changed")
    require(fresh["support"]["selected"] == target["support"]["selected"], "matched support profile changed")
    latest = network(args, fresh, "snapshot")
    eligibility = assess_eligibility(latest, args, baseline)
    require_eligible(eligibility)
    require(assess_failure(latest, args.peer_id)["applicable"], "peer state changed, reinspect")
    chosen = select(args, fresh, latest)
    require(chosen["socket"] == candidate["socket"], "reader socket changed, reinspect")
    require(identity(fresh["process"]["pid"]) == fresh["process"], "process identity changed")
    return {"target": fresh, "snapshot": latest, "candidate": chosen, "eligibility": eligibility}


def close_one_reader(args, plan):
    """The sole mutation: destroy one cookie-qualified socket, with no close retry."""
    return network(args, plan["target"], "destroy", socket=plan["candidate"]["socket"])


def verify_recovery(args, plan, report, audit_fd):
    """Observe a bounded recovery window; never retry or broaden the repair."""
    target, baseline = plan["target"], plan["snapshot"]
    state = {"indexes": {m["id"]: int(m["status"]["raftAppliedIndex"])
                         for m in baseline["members"] if m["healthy"]}, "stable_since": None}
    started = time.monotonic()
    while time.monotonic() - started < args.verify_timeout:
        require(identity(target["process"]["pid"]) == target["process"], "process changed after close")
        try:
            current = network(args, target, "snapshot")
            state = verification_step(state, current, args, baseline, time.monotonic() - started)
            report["verification"].append({"snapshot": current, "decision": state})
        except (Refusal, OSError, ValueError, KeyError, subprocess.TimeoutExpired,
                http.client.HTTPException) as error:
            state = dict(state, stable_since=None)
            report["verification"].append({"time": now(), "error": str(error)})
        write_audit(audit_fd, report)
        if state.get("complete") and "error" not in report["verification"][-1]:
            return
        time.sleep(1)
    raise Refusal("verification timed out after one close; no further closes attempted")


def inspect_and_repair(args, report, audit_fd):
    """Orchestrate support -> eligibility -> applicability -> selection -> one close -> verification."""
    target = prepare_target(args)
    report["target"] = audit_target(target)
    report["support"] = target["support"]
    if target["support"]["supported"]:
        report["validation"] = supported_profile(target["support"])["validation"]
    if args.expect_profile_id:
        require(target["support"]["supported"] and target["support"]["selected"]["profile_id"] == args.expect_profile_id,
                "expected support profile mismatch")
    if args.mode == "repair":
        supported_profile(target["support"])
    baseline = network(args, target, "snapshot")
    report["before"] = baseline
    report["eligibility"] = assess_eligibility(baseline, args)
    report["applicability"] = assess_failure(baseline, args.peer_id)
    if not target["support"]["supported"]:
        report["outcome"] = "unsupported_inspection_no_action"
        return 2
    require_eligible(report["eligibility"])
    if report["applicability"]["already_active"]:
        report["outcome"] = "already_active_no_action"
        return 0
    require(report["applicability"]["applicable"], report["applicability"]["reason"])
    report["candidate"] = select(args, target, baseline)
    if args.mode == "inspect":
        report["outcome"] = "candidate_identified_no_action"
        return 0
    plan = revalidate_plan(args, target, baseline, report["candidate"])
    report["pre_close"] = plan["snapshot"]
    report["pre_close_eligibility"] = plan["eligibility"]
    report["close_attempted"] = True
    report["outcome"] = "close_requested_verification_incomplete"
    write_audit(audit_fd, report)
    report["mutations"].append(close_one_reader(args, plan))
    write_audit(audit_fd, report)
    verify_recovery(args, plan, report, audit_fd)
    report["outcome"] = "reconnected_and_verified"
    return 0


def assess_collection(path, binary_path=None):
    """Report offline support without implying that saved health or sockets are current."""
    raw = pathlib.Path(path).read_bytes()
    collection = json.loads(raw)
    facts = collection_facts(collection)
    if binary_path:
        digest = hashlib.sha256()
        with open(binary_path, "rb") as stream:
            for block in iter(lambda: stream.read(1024 * 1024), b""):
                digest.update(block)
        require(digest.hexdigest() == facts["executable_sha256"], "binary does not match collection SHA256")
    assessment = assess_support(facts)
    return {"version": VERSION, "collection_sha256": hashlib.sha256(raw).hexdigest(),
            "binary_verified": bool(binary_path), "support": assessment,
            "scope": "offline binary compatibility only; repair requires fresh live eligibility checks",
            "validation": supported_profile(assessment)["validation"] if assessment["supported"] else None}


def parse_args(argv=None):
    """Separate offline assessment from host operations without adding bypass flags."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("mode", choices=["check-support", "inspect", "repair"])
    parser.add_argument("--collection", help="collector report.json for offline check-support")
    parser.add_argument("--binary", help="optional exported executable to verify against collection")
    parser.add_argument("--runtime-endpoint")
    parser.add_argument("--namespace")
    parser.add_argument("--pod")
    parser.add_argument("--peer-id", help="current remote member ID, hexadecimal")
    parser.add_argument("--expect-cluster-id")
    parser.add_argument("--expect-member-id")
    parser.add_argument("--expect-profile-id", help="optional profile identity pin; not an override")
    parser.add_argument("--crictl", default="crictl")
    parser.add_argument("--nsenter", default="nsenter")
    for name in ["ca", "cert", "key", "server-name"]:
        parser.add_argument("--" + name)
    parser.add_argument("--client-port", type=int)
    parser.add_argument("--metrics-port", type=int)
    parser.add_argument("--stable-seconds", type=float, default=10)
    parser.add_argument("--verify-timeout", type=float, default=45)
    parser.add_argument("--report", help="new JSON audit filename, mode 0600")
    parser.add_argument("--version", action="version", version=VERSION)
    return parser.parse_args(argv)


def validate_arguments(args):
    """Validate invocation inputs without changing the caller's argument object."""
    normalized = argparse.Namespace(**vars(args))
    if args.mode == "check-support":
        require(args.collection, "check-support requires --collection")
        return normalized
    require(args.runtime_endpoint and args.namespace and args.pod and args.peer_id,
            "host operations require --runtime-endpoint, --namespace, --pod and --peer-id")
    require(sys.platform == "linux" and os.geteuid() == 0, "Linux root privileges required")
    require(args.stable_seconds >= 6 and args.verify_timeout > args.stable_seconds + 5,
            "verification must allow at least six stable seconds plus recovery time")
    for name in ["peer_id", "expect_cluster_id", "expect_member_id"]:
        if getattr(args, name):
            setattr(normalized, name, format(int(getattr(args, name), 16), "x"))
    if args.mode == "repair":
        require(args.expect_cluster_id and args.expect_member_id and args.report,
                "repair requires both expected IDs and a new --report path")
    for name in ["crictl", "nsenter"]:
        value = shutil.which(getattr(args, name))
        require(value, "required executable not found: " + name)
        setattr(normalized, name, value)
    return normalized


def main():
    args = parse_args()
    report = {"version": VERSION, "started": now(), "mode": args.mode,
              "mutations": [], "verification": []}
    audit_fd, exit_code = None, 2
    try:
        args = validate_arguments(args)
        audit_fd = open_audit(args.report)
        write_audit(audit_fd, report)
        if args.mode == "check-support":
            report.update(assess_collection(args.collection, args.binary))
            report["outcome"] = "supported_collection" if report["support"]["supported"] else "unsupported_collection"
            exit_code = 0 if report["support"]["supported"] else 2
        else:
            exit_code = inspect_and_repair(args, report, audit_fd)
    except (Refusal, OSError, ValueError, KeyError, TypeError, StopIteration,
            subprocess.TimeoutExpired, http.client.HTTPException) as error:
        report["outcome"] = ("close_requested_verification_incomplete" if report.get("close_attempted")
                             else "refused_no_action")
        report["error"] = str(error)
    except KeyboardInterrupt:
        report["outcome"] = ("close_requested_verification_incomplete" if report.get("close_attempted")
                             else "interrupted_no_action")
        report["error"] = "operator interrupted the program"
    report["finished"] = now()
    try:
        write_audit(audit_fd, report)
    except (OSError, Refusal) as error:
        report["audit_error"] = str(error)
        report["outcome"] = ("close_requested_verification_incomplete" if report.get("close_attempted")
                             else "refused_no_action")
        exit_code = 2
    finally:
        if audit_fd is not None:
            os.close(audit_fd)
    print(json.dumps(report, indent=2))
    return exit_code


if __name__ == "__main__":
    if len(sys.argv) == 2 and sys.argv[1] == "_netop":
        try:
            print(json.dumps(netop(json.load(sys.stdin))))
        except Exception as error:
            print(str(error), file=sys.stderr)
            sys.exit(2)
    else:
        sys.exit(main())
