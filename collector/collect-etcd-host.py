#!/usr/bin/env python3
"""Collect read-only etcd host evidence into a JSON report and binary archive."""
import argparse
import datetime
import hashlib
import json
import os
import pathlib
import platform
import re
import subprocess
import sys
import tarfile
import tempfile

VERSION = "4.0.0"
SCHEMA_VERSION = 2
ALLOWED = {"name", "advertise-client-urls", "listen-client-urls",
           "initial-advertise-peer-urls", "listen-peer-urls", "trusted-ca-file",
           "cert-file", "key-file", "peer-trusted-ca-file", "peer-cert-file",
           "peer-key-file", "client-cert-auth", "peer-client-cert-auth",
           "listen-metrics-urls", "strict-reconfig-check", "heartbeat-interval",
           "election-timeout", "peer-skip-client-san-verification",
           "peer-cert-allowed-cn", "peer-cert-allowed-hostname"}


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


def collect_container_identity(cri, container_id):
    """Select only the container identity and pin its running etcd process."""
    detail = cri_json(cri + ["inspect", container_id])
    info = detail.get("info", {})
    if isinstance(info, str):
        info = json.loads(info)
    status = detail.get("status", {})
    pid = int(info.get("pid", 0))
    root = pathlib.Path("/proc/{}".format(pid))
    if pid <= 1 or (root / "comm").read_text().strip() != "etcd":
        raise RuntimeError("selected running process is not etcd")
    labels = status.get("labels", {})
    return {"pid": pid, "start_ticks": start_ticks(pid),
            "container_id": status.get("id"),
            "image": status.get("image", {}).get("image"), "image_ref": status.get("imageRef"),
            "pod": {k: labels.get(k) for k in ["io.kubernetes.pod.name", "io.kubernetes.pod.namespace"]}}


def collect_etcd_environment(pid):
    """Read only reproduction-relevant ETCD_* settings; never dump the environment."""
    env = {}
    for item in pathlib.Path("/proc/{}/environ".format(pid)).read_bytes().split(b"\0"):
        key, sep, value = item.partition(b"=")
        key = key.decode("utf-8", "replace")
        if sep and key.startswith("ETCD_") and key[5:].lower().replace("_", "-") in ALLOWED:
            env[key] = value.decode("utf-8", "replace")
    return env


def collect_etcd_arguments(pid):
    """Read the same allowlisted settings from command-line flags."""
    flags = {}
    argv = pathlib.Path("/proc/{}/cmdline".format(pid)).read_bytes().decode("utf-8", "replace").split("\0")
    for i, arg in enumerate(argv):
        key, eq, value = arg[2:].partition("=") if arg.startswith("--") else ("", "", "")
        if key in ALLOWED:
            flags[key] = value if eq else (argv[i+1] if i+1 < len(argv) else "")
    return flags


def collect_executable(pid, destination):
    """Always export and hash one open executable; never publish a partial copy."""
    digest = hashlib.sha256()
    source = "/proc/{}/exe".format(pid)
    partial = destination.with_name(destination.name + ".partial")
    with open(source, "rb") as src, open(str(partial), "xb") as dst:
        inode = os.fstat(src.fileno()).st_ino
        for block in iter(lambda: src.read(1024 * 1024), b""):
            digest.update(block)
            dst.write(block)
    partial.rename(destination)
    return {"source": source, "inode": inode, "sha256": digest.hexdigest(),
            "exported_file": destination.name}


def parse_active_peer_metrics(result):
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


def collect_host_os():
    """Record only OS identity/version, not vendor links or unrelated release metadata."""
    result = read_check("/etc/os-release")
    if result["status"] == "ok":
        fields = {}
        for line in result.pop("value").splitlines():
            key, sep, value = line.partition("=")
            if sep and key in {"ID", "VERSION_ID"}:
                fields[key] = value.strip('"')
        result["data"] = fields
    return result


def collect_host():
    """Identify the kernel, architecture and host OS needed to match the platform."""
    return {"kernel_release": platform.release(), "architecture": platform.machine(),
            "os_release": collect_host_os()}


def collect_container_candidates(cri):
    """List running etcd candidates without exporting the raw CRI response."""
    data = cri_json(cri + ["ps", "--name", "^etcd$", "-o", "json"])
    return [{"id": c.get("id"), "namespace": c.get("labels", {}).get("io.kubernetes.pod.namespace"),
             "pod": c.get("labels", {}).get("io.kubernetes.pod.name")}
            for c in data.get("containers", []) if c.get("metadata", {}).get("name") == "etcd"]


def collect_etcd_version(cri, container_id):
    """Record etcd, Go and build versions from the selected container."""
    return command(cri + ["exec", container_id, "etcd", "--version"])


def collect_dns_configuration(pid):
    """Capture the container resolver configuration used by peer SAN lookups."""
    return read_check("/proc/{}/root/etc/resolv.conf".format(pid))


def container_path(pid, value):
    """Validate a mounted path before any host-side credential/certificate access."""
    path = pathlib.PurePosixPath(value)
    if not path.is_absolute() or ".." in path.parts:
        raise ValueError("container path must be absolute and contain no ..")
    return "/proc/{}/root{}".format(pid, value)


def collect_client_tls_paths(pid, args):
    """Record credential paths and readability, without reading their contents."""
    paths = {"ca": args.cacert, "cert": args.cert, "key": args.key}
    files = {}
    for name, value in paths.items():
        try:
            readable = os.access(container_path(pid, value), os.R_OK)
            files[name] = {"status": "ok" if readable else "failed"}
            if not readable:
                files[name]["error"] = "path is not readable"
        except ValueError as error:
            files[name] = {"status": "failed", "error": str(error)}
    return {"container_paths": paths, "files": files}


def collect_peer_certificate(pid, configuration):
    """Record the public peer certificate identity, validity and SANs for TLS reproduction."""
    path = configuration["flags"].get("peer-cert-file") or configuration["env"].get("ETCD_PEER_CERT_FILE")
    if not path:
        return {"status": "skipped", "reason": "peer certificate path not configured"}
    try:
        mounted = container_path(pid, path)
    except ValueError as error:
        return {"status": "failed", "error": str(error)}
    return command(["openssl", "x509", "-in", mounted, "-noout", "-subject", "-issuer",
                    "-dates", "-ext", "subjectAltName"])


def etcdctl_command(cri, container_id, args):
    """Build authenticated local diagnostics with bounded dial and request times."""
    return cri + ["exec", container_id, "etcdctl", "--endpoints=https://localhost:2379",
                  "--cacert=" + args.cacert, "--cert=" + args.cert, "--key=" + args.key,
                  "--dial-timeout=3s", "--command-timeout=5s"]


def collect_etcd_status(ctl):
    """Record local member/cluster IDs, leader, term and applied index."""
    return json_result(command(ctl + ["endpoint", "status", "-w", "json"]))


def collect_etcd_members(ctl):
    """Record current voters/learners and advertised client/peer URLs."""
    return json_result(command(ctl + ["member", "list", "-w", "json"]))


def collect_etcd_health(ctl):
    """Check whether the selected member currently serves an authenticated health probe."""
    return json_result(command(ctl + ["endpoint", "health", "-w", "json"]))


def collect_active_peers(pid, args):
    """Capture only the peer-status metric, using verified TLS in the etcd netns."""
    result = command(["nsenter", "-t", str(pid), "-n", "--", "curl", "--silent",
                      "--show-error", "--fail", "--max-time", "8", "--noproxy", "*",
                      "--cacert", container_path(pid, args.cacert),
                      "--cert", container_path(pid, args.cert),
                      "--key", container_path(pid, args.key),
                      "https://localhost:2382/metrics"], timeout=12)
    return parse_active_peer_metrics(result)


def verify_process_identity(process, executable):
    """Reject a report mixing observations from a restarted process or changed binary."""
    pid = process["pid"]
    if (start_ticks(pid) != process["start_ticks"] or
            os.stat("/proc/{}/exe".format(pid)).st_ino != executable["inode"]):
        raise RuntimeError("process or executable changed during collection; rerun")


def collect(args, report, work):
    """Collection order; each named operation owns the evidence it gathers."""
    report["host"] = collect_host()
    cri = ["crictl"]
    if args.runtime_endpoint:
        cri += ["--runtime-endpoint", args.runtime_endpoint]
    cid = args.container
    if not cid:
        report["candidates"] = collect_container_candidates(cri)
        if len(report["candidates"]) != 1:
            raise RuntimeError("expected one etcd container; select --container ID")
        cid = report["candidates"][0]["id"]
    report["process"] = collect_container_identity(cri, cid)
    pid = report["process"]["pid"]
    report["configuration"] = {}
    report["configuration"]["env"] = collect_etcd_environment(pid)
    report["configuration"]["flags"] = collect_etcd_arguments(pid)
    report["executable"] = collect_executable(pid, work / "etcd-executable")
    report["tls"] = collect_client_tls_paths(pid, args)
    checks = report["checks"]
    checks["etcd_version"] = collect_etcd_version(cri, cid)
    checks["dns_configuration"] = collect_dns_configuration(pid)
    checks["peer_certificate"] = collect_peer_certificate(pid, report["configuration"])
    if all(x["status"] == "ok" for x in report["tls"]["files"].values()):
        ctl = etcdctl_command(cri, cid, args)
        checks["etcd_status"] = collect_etcd_status(ctl)
        checks["etcd_members"] = collect_etcd_members(ctl)
        checks["etcd_health"] = collect_etcd_health(ctl)
        checks["active_peers"] = collect_active_peers(pid, args)
    else:
        for name in ["etcd_status", "etcd_members", "etcd_health", "active_peers"]:
            checks[name] = {"status": "skipped", "reason": "client TLS paths unavailable or invalid"}
    verify_process_identity(report["process"], report["executable"])
    report["process_identity_verified_at_end"] = True


def create_output_directory(args, report):
    """Create a private working directory and record the artifact paths."""
    work = pathlib.Path(tempfile.mkdtemp(prefix="etcd-host-report-", dir=args.output_dir)).resolve()
    report["artifacts"] = {"report": str(work / "report.json"), "working_directory": str(work),
                           "archive": str(work) + ".tar.gz", "checksum": str(work) + ".tar.gz.sha256"}
    return work


def write_report(work, report):
    """Save structured evidence in the results directory and archive."""
    (work / "report.json").write_text(json.dumps(report, indent=2) + "\n")


def create_archive(work, archive):
    """Require both report and executable in every archive."""
    with tarfile.open(str(archive), "w:gz") as tar:
        tar.add(str(work / "report.json"), arcname=work.name + "/report.json")
        tar.add(str(work / "etcd-executable"), arcname=work.name + "/etcd-executable")


def write_archive_checksum(archive):
    """Write a SHA-256 sidecar for the generated archive."""
    digest = hashlib.sha256()
    with open(str(archive), "rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    pathlib.Path(str(archive) + ".sha256").write_text(digest.hexdigest() + "  " + archive.name + "\n")


def print_results(report):
    """Tell the operator where saved evidence lives, without requiring redirection."""
    completed = report["collection_status"] == "completed"
    if completed:
        print("Collection complete.")
    else:
        print("Collection failed: " + report.get("error", "could not package results"), file=sys.stderr)
    if report.get("packaging_error"):
        print("Could not save all results: " + report["packaging_error"], file=sys.stderr)
    artifacts = report.get("artifacts", {})
    for name, label in [("report", "Report"), ("archive", "Archive"), ("checksum", "Checksum")]:
        path = artifacts.get(name)
        if path and os.path.isfile(path):
            print("{}: {}".format(label, path))
    if completed:
        issues = sum(check["status"] != "ok" for check in report["checks"].values())
        if issues:
            print("{} check(s) need attention; see the report for details.".format(issues))
        print("Send the archive and checksum files.")


def main():
    parser = argparse.ArgumentParser(prog="collect-etcd-host.py", description="Read-only etcd host collection; saves a JSON report and executable archive.")
    parser.add_argument("--container", help="running etcd container ID; auto-select if exactly one")
    parser.add_argument("--runtime-endpoint", help="otherwise use host crictl configuration")
    parser.add_argument("--cacert", default="/etc/etcd/tls/etcd-ca/ca.crt", help="CA path inside container")
    parser.add_argument("--cert", default="/etc/etcd/tls/client/etcd-client.crt", help="client cert path inside container")
    parser.add_argument("--key", default="/etc/etcd/tls/client/etcd-client.key", help="client key path inside container")
    parser.add_argument("--output-dir", default=".", help="existing directory for report archive")
    parser.add_argument("--version", action="version", version=VERSION)
    args = parser.parse_args()
    os.umask(0o077)
    report = {"schema_version": SCHEMA_VERSION, "collector_version": VERSION, "started_at": utc(),
              "collection_status": "failed", "checks": {},
              "runtime_endpoint": args.runtime_endpoint,
              "runtime_endpoint_source": "argument" if args.runtime_endpoint else "host crictl configuration",
              "scope": "read-only diagnostics; no key contents, datastore files, full environment or full CRI responses"}
    work = None
    try:
        if sys.platform != "linux" or os.geteuid() != 0:
            raise RuntimeError("run as root on the Linux etcd host")
        work = create_output_directory(args, report)
        collect(args, report, work)
        report["collection_status"] = "completed"
    except (OSError, ValueError, KeyError, TypeError, RuntimeError) as e:
        report["error"] = str(e)
    report["finished_at"] = utc()
    if work and "executable" not in report:
        # Partial JSON is useful for troubleshooting; it is not a usable package.
        report["artifacts"]["archive"] = None
        report["artifacts"]["checksum"] = None
        try:
            write_report(work, report)
        except OSError as error:
            report["packaging_error"] = str(error)
    elif work:
        try:
            write_report(work, report)
            archive = pathlib.Path(report["artifacts"]["archive"])
            create_archive(work, archive)
            write_archive_checksum(archive)
        except OSError as e:
            report.update(collection_status="failed", packaging_error=str(e))
            report["artifacts"]["archive"] = None
            report["artifacts"]["checksum"] = None
            # Keep the partial JSON current even when archive generation failed.
            try:
                write_report(work, report)
            except OSError:
                pass
    print_results(report)
    return 0 if report["collection_status"] == "completed" else 2


if __name__ == "__main__":
    sys.exit(main())
