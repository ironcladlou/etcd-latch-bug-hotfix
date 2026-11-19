#!/usr/bin/env bash
# Single-file, read-only collector. Python stdlib builds the report as JSON.
set -eu
exec python3 - "$@" <<'PYTHON'
import argparse
import datetime
import hashlib
import json
import os
import pathlib
import platform
import re
import shutil
import ssl
import subprocess
import sys
import tarfile
import tempfile

VERSION = "2.0.0"
ALLOWED = {"name", "advertise-client-urls", "listen-client-urls",
           "initial-advertise-peer-urls", "listen-peer-urls", "trusted-ca-file",
           "cert-file", "key-file", "peer-trusted-ca-file", "peer-cert-file",
           "peer-key-file", "client-cert-auth", "peer-client-cert-auth",
           "listen-metrics-urls"}


def utc():
    return datetime.datetime.now(datetime.timezone.utc).isoformat()


def command(argv, timeout=20):
    """No shell, no retries; failures retain stdout and stderr separately."""
    try:
        p = subprocess.run(argv, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                           universal_newlines=True, errors="replace", timeout=timeout)
        return {"status": "ok" if p.returncode == 0 else "failed",
                "exit_code": p.returncode, "stdout": p.stdout, "stderr": p.stderr}
    except subprocess.TimeoutExpired as e:
        def decode(value):
            return value.decode("utf-8", "replace") if isinstance(value, bytes) else value or ""
        return {"status": "timeout", "exit_code": None,
                "stdout": decode(e.stdout), "stderr": decode(e.stderr),
                "error": "command exceeded {} seconds".format(timeout)}
    except OSError as e:
        return {"status": "unavailable", "exit_code": None, "error": str(e)}


def json_result(result):
    if result["status"] == "ok":
        try:
            result["data"] = json.loads(result["stdout"])
            result.pop("stdout")
        except ValueError as e:
            result.update(status="invalid_json", error=str(e))
    return result


def cri_json(argv):
    # Never retain raw ps/inspect output, including on JSON/command failure.
    result = command(argv)
    if result["status"] != "ok":
        raise RuntimeError("CRI diagnostic failed ({}, exit={})".format(
            result["status"], result["exit_code"]))
    try:
        return json.loads(result["stdout"])
    except ValueError:
        raise RuntimeError("CRI returned invalid JSON; raw response excluded")


def start_ticks(pid):
    text = pathlib.Path("/proc/{}/stat".format(pid)).read_text()
    return text[text.rfind(")") + 2:].split()[19]


def process_metadata(detail):
    info = detail.get("info", {})
    if isinstance(info, str):
        info = json.loads(info)
    status = detail.get("status", {})
    pid = int(info.get("pid", 0))
    root = pathlib.Path("/proc/{}".format(pid))
    if pid <= 1 or (root / "comm").read_text().strip() != "etcd":
        raise RuntimeError("selected running process is not etcd")
    start = start_ticks(pid)
    env, flags = {}, {}
    for item in (root / "environ").read_bytes().split(b"\0"):
        key, sep, value = item.partition(b"=")
        key = key.decode("utf-8", "replace")
        if sep and key.startswith("ETCD_") and key[5:].lower().replace("_", "-") in ALLOWED:
            env[key] = value.decode("utf-8", "replace")
    argv = (root / "cmdline").read_bytes().decode("utf-8", "replace").split("\0")
    for i, arg in enumerate(argv):
        key, eq, value = arg[2:].partition("=") if arg.startswith("--") else ("", "", "")
        if key in ALLOWED:
            flags[key] = value if eq else (argv[i+1] if i+1 < len(argv) else "")
    labels = status.get("labels", {})
    meta = {"pid": pid, "start_ticks": start, "container_id": status.get("id"),
            "image": status.get("image", {}).get("image"), "image_ref": status.get("imageRef"),
            "pod": {k: labels.get(k) for k in ["io.kubernetes.pod.name", "io.kubernetes.pod.namespace"]},
            "env": env, "flags": flags, "netns": os.readlink(str(root / "ns/net"))}
    try:
        fd = os.open(str(root / "mem"), os.O_RDONLY)
        os.close(fd)
        meta["proc_mem_open"] = {"status": "ok", "memory_read": False}
    except OSError as e:
        meta["proc_mem_open"] = {"status": "failed", "memory_read": False, "error": str(e)}
    return meta


def executable(pid, destination=None):
    # One open file pins the executable across hashing and optional export.
    digest = hashlib.sha256()
    source = "/proc/{}/exe".format(pid)
    with open(source, "rb") as src:
        inode = os.fstat(src.fileno()).st_ino
        if destination:
            with open(str(destination), "xb") as dst:
                for block in iter(lambda: src.read(1024 * 1024), b""):
                    digest.update(block)
                    dst.write(block)
        else:
            for block in iter(lambda: src.read(1024 * 1024), b""):
                digest.update(block)
    return {"source": source, "inode": inode, "sha256": digest.hexdigest(),
            "exported_file": destination.name if destination else None}


def active_peers(result):
    raw, samples = [], []
    if result["status"] == "ok":
        for line in result.get("stdout", "").splitlines():
            if line.startswith(("# HELP etcd_network_active_peers ",
                                "# TYPE etcd_network_active_peers ")):
                raw.append(line)
            match = re.fullmatch(r'etcd_network_active_peers\{([^}]+)\}\s+([01](?:\.0)?)', line)
            if match:
                raw.append(line)
                samples.append({"labels": dict(re.findall(r'(\w+)="([^"]*)"', match.group(1))),
                                "value": int(float(match.group(2)))})
        if not samples:
            result.update(status="missing_metric", error="no active-peer samples returned")
    # Do not retain unrelated metrics or HTTP error response bodies.
    result.pop("stdout", None)
    result.update(samples=samples, raw="\n".join(raw) + ("\n" if raw else ""))
    return result


def read_check(path):
    try:
        return {"status": "ok", "value": pathlib.Path(path).read_text().strip()}
    except OSError as e:
        return {"status": "unavailable", "error": str(e)}


def collect(args, report, work):
    checks = report["checks"]
    report["host"] = {"kernel_release": platform.release(), "architecture": platform.machine(),
                      "os_release": read_check("/etc/os-release"),
                      "python_version": sys.version, "openssl_version": ssl.OPENSSL_VERSION}
    for name, cmd in [("crictl", ["crictl", "--version"]), ("ss", ["ss", "-V"]),
                      ("nsenter", ["nsenter", "--version"]), ("curl", ["curl", "--version"]),
                      ("selinux", ["getenforce"])]:
        checks[name] = command(cmd)
    checks["ptrace_scope"] = read_check("/proc/sys/kernel/yama/ptrace_scope")
    cri = ["crictl"]
    if args.runtime_endpoint:
        cri += ["--runtime-endpoint", args.runtime_endpoint]
    cid = args.container
    if not cid:
        data = cri_json(cri + ["ps", "--name", "^etcd$", "-o", "json"])
        candidates = [c for c in data.get("containers", []) if c.get("metadata", {}).get("name") == "etcd"]
        report["candidates"] = [{"id": c.get("id"), "namespace": c.get("labels", {}).get("io.kubernetes.pod.namespace"),
                                 "pod": c.get("labels", {}).get("io.kubernetes.pod.name")} for c in candidates]
        if len(candidates) != 1:
            raise RuntimeError("expected one etcd container; select --container ID")
        cid = candidates[0]["id"]
    meta = process_metadata(cri_json(cri + ["inspect", cid]))
    report["process"] = meta
    pid = meta["pid"]
    report["executable"] = executable(pid, work / "etcd-executable" if args.include_binary else None)
    checks["executable_format"] = command(["file", "-L", "/proc/{}/exe".format(pid)])
    checks["etcd_version"] = command(cri + ["exec", cid, "etcd", "--version"])
    checks["peer_sockets"] = command(["nsenter", "-t", str(pid), "-n", "--", "ss", "-Hntie",
                                       "( sport = :2380 or dport = :2380 )"])
    paths = {"ca": args.cacert, "cert": args.cert, "key": args.key}
    tls = report["tls"] = {"container_paths": paths, "files": {}}
    for name, value in paths.items():
        path = pathlib.PurePosixPath(value)
        valid = path.is_absolute() and ".." not in path.parts
        readable = valid and os.access("/proc/{}/root{}".format(pid, value), os.R_OK)
        tls["files"][name] = {"status": "ok" if readable else "failed",
                              "error": None if readable else "path must be absolute, contain no .., and be readable"}
    if all(x["status"] == "ok" for x in tls["files"].values()):
        root = "/proc/{}/root".format(pid)
        checks["client_certificate"] = command(["openssl", "x509", "-in", root + args.cert,
            "-noout", "-subject", "-issuer", "-dates", "-ext", "subjectAltName"])
        ctl = cri + ["exec", cid, "etcdctl", "--endpoints=https://localhost:2379",
                     "--cacert=" + args.cacert, "--cert=" + args.cert, "--key=" + args.key,
                     "--dial-timeout=3s", "--command-timeout=5s"]
        for name, cmd in [("etcd_status", ["endpoint", "status"]),
                          ("etcd_members", ["member", "list"]), ("etcd_health", ["endpoint", "health"])]:
            checks[name] = json_result(command(ctl + cmd + ["-w", "json"]))
        checks["active_peers"] = active_peers(command(["nsenter", "-t", str(pid), "-n", "--",
            "curl", "--silent", "--show-error", "--fail", "--max-time", "8", "--noproxy", "*",
            "--cacert", root + args.cacert, "--cert", root + args.cert, "--key", root + args.key,
            "https://localhost:2382/metrics"], timeout=12))
    else:
        for name in ["client_certificate", "etcd_status", "etcd_members", "etcd_health", "active_peers"]:
            checks[name] = {"status": "skipped", "reason": "client TLS paths unavailable or invalid"}
    if start_ticks(pid) != meta["start_ticks"] or os.stat("/proc/{}/exe".format(pid)).st_ino != report["executable"]["inode"]:
        raise RuntimeError("process or executable changed during collection; rerun")
    report["process_identity_verified_at_end"] = True


def main():
    parser = argparse.ArgumentParser(prog="collect-etcd-host.sh", description="Read-only etcd host prerequisites; emits JSON on stdout.")
    parser.add_argument("--container", help="running etcd container ID; auto-select if exactly one")
    parser.add_argument("--runtime-endpoint", help="otherwise use host crictl configuration")
    parser.add_argument("--cacert", default="/etc/etcd/tls/etcd-ca/ca.crt", help="CA path inside container")
    parser.add_argument("--cert", default="/etc/etcd/tls/client/etcd-client.crt", help="client cert path inside container")
    parser.add_argument("--key", default="/etc/etcd/tls/client/etcd-client.key", help="client key path inside container")
    parser.add_argument("--include-binary", action="store_true", help="include running executable; no data files")
    parser.add_argument("--output-dir", default=".", help="existing directory for report archive")
    parser.add_argument("--version", action="version", version=VERSION)
    args = parser.parse_args()
    os.umask(0o077)
    report = {"schema_version": 1, "collector_version": VERSION, "started_at": utc(),
              "collection_status": "failed", "checks": {},
              "runtime_endpoint": args.runtime_endpoint,
              "runtime_endpoint_source": "argument" if args.runtime_endpoint else "host crictl configuration",
              "scope": "read-only diagnostics; no key contents, datastore files, full environment or full CRI responses"}
    work = None
    try:
        if sys.platform != "linux" or os.geteuid() != 0:
            raise RuntimeError("run as root on the Linux etcd host")
        work = pathlib.Path(tempfile.mkdtemp(prefix="etcd-host-report-", dir=args.output_dir)).resolve()
        archive = pathlib.Path(str(work) + ".tar.gz")
        report["artifacts"] = {"report": str(work / "report.json"), "working_directory": str(work),
                               "archive": str(archive), "checksum": str(archive) + ".sha256"}
        collect(args, report, work)
        report["collection_status"] = "completed"
    except (OSError, ValueError, KeyError, TypeError, RuntimeError) as e:
        report["error"] = str(e)
    report["finished_at"] = utc()
    if work:
        try:
            # This exact object is both retained in the archive and emitted on stdout.
            (work / "report.json").write_text(json.dumps(report, indent=2) + "\n")
            with tarfile.open(str(archive), "w:gz") as tar:
                tar.add(str(work / "report.json"), arcname=work.name + "/report.json")
                if (work / "etcd-executable").exists():
                    tar.add(str(work / "etcd-executable"), arcname=work.name + "/etcd-executable")
            digest = hashlib.sha256()
            with open(str(archive), "rb") as stream:
                for block in iter(lambda: stream.read(1024 * 1024), b""):
                    digest.update(block)
            pathlib.Path(str(archive) + ".sha256").write_text(digest.hexdigest() + "  " + archive.name + "\n")
        except OSError as e:
            report.update(collection_status="failed", packaging_error=str(e))
            # Keep the partial JSON current even when archive generation failed.
            try:
                (work / "report.json").write_text(json.dumps(report, indent=2) + "\n")
            except OSError:
                pass
    print(json.dumps(report, indent=2))
    return 0 if report["collection_status"] == "completed" else 2


if __name__ == "__main__":
    sys.exit(main())
PYTHON
