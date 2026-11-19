#!/usr/bin/env bash
# Read-only host diagnostics. Never exports keys, full CRI inspect, or full env.
set -eu
umask 077
usage() {
  cat <<'EOF'
Usage: sudo bash collect-etcd-host.sh [options]
  --container ID             Running etcd container (auto-select if exactly one)
  --runtime-endpoint URL     Otherwise use the host's crictl configuration
  --cacert PATH              CA path INSIDE container
  --cert PATH                Client certificate path INSIDE container
  --key PATH                 Client key path INSIDE container
  --include-binary           Include running etcd executable (no data files)
  --output-dir DIR           Existing directory for the resulting .tar.gz

Run on each serving etcd host. Defaults for TLS paths are HyperShift paths;
if those do not exist, supply the actual container paths. Failed/unsupported
checks are recorded. No sockets are closed and no configuration is changed.
EOF
}
cid= endpoint= include=0 out=.
ca=/etc/etcd/tls/etcd-ca/ca.crt
cert=/etc/etcd/tls/client/etcd-client.crt
key=/etc/etcd/tls/client/etcd-client.key
while [ "$#" -gt 0 ]; do
  case "$1" in
    --container|--runtime-endpoint|--cacert|--cert|--key|--output-dir)
      [ "$#" -ge 2 ] || { usage >&2; exit 2; }
      case "$1" in
        --container) cid=$2;; --runtime-endpoint) endpoint=$2;;
        --cacert) ca=$2;; --cert) cert=$2;; --key) key=$2;; --output-dir) out=$2;;
      esac
      shift 2;;
    --include-binary) include=1; shift;;
    -h|--help) usage; exit 0;;
    *) usage >&2; exit 2;;
  esac
done
[ "$(id -u)" = 0 ] || { echo 'Run as root on the etcd host.' >&2; exit 2; }
for tool in python3 crictl timeout tar sha256sum; do
  command -v "$tool" >/dev/null || { echo "Required tool missing: $tool" >&2; exit 2; }
done
[ -d "$out" ] || { echo 'Output directory must exist.' >&2; exit 2; }
work=$(mktemp -d "$out/etcd-host-report-XXXXXXXX")
report=$work/report.txt
# Keep partial evidence on error. Never store the raw CRI response on disk.
cri=(crictl)
[ -z "$endpoint" ] || cri+=(--runtime-endpoint "$endpoint")
section() { printf '\n### %s\n' "$1"; }
check() {
  if timeout 20 "$@"; then :; else
    rc=$?; printf '[check failed or unavailable; exit=%s]\n' "$rc"
  fi
}
{
  echo 'etcd host prerequisite collector v1'
  date -u '+UTC %Y-%m-%dT%H:%M:%SZ'
  echo 'No fault injection, configuration changes, key contents, or data files collected.'
  section 'Host and tools'
  check uname -r -m
  [ ! -r /etc/os-release ] || cat /etc/os-release
  check python3 -c 'import sys,ssl; print(sys.version); print(ssl.OPENSSL_VERSION)'
  check crictl --version
  check ss -V
  check nsenter --version
  check curl --version
  check getenforce
  check cat /proc/sys/kernel/yama/ptrace_scope
  printf 'CRI endpoint argument: %s\n' "${endpoint:-<host crictl configuration>}"
} > "$report" 2>&1
if [ -z "$cid" ]; then
  cid=$(timeout 20 "${cri[@]}" ps --name '^etcd$' -o json | python3 -c '
import json,sys
cs=[c for c in json.load(sys.stdin).get("containers",[]) if c.get("metadata",{}).get("name")=="etcd"]
if len(cs)!=1:
    print("Select --container ID; found %d etcd containers" % len(cs),file=sys.stderr)
    for c in cs:
        print(c.get("id"), c.get("labels",{}).get("io.kubernetes.pod.namespace"), c.get("labels",{}).get("io.kubernetes.pod.name"),file=sys.stderr)
    sys.exit(2)
print(cs[0]["id"])
') || { echo "Selection failed; partial report: $report" >&2; exit 2; }
fi
# Only allowlisted CRI/process metadata crosses this filter.
timeout 20 "${cri[@]}" inspect "$cid" | python3 -c '
import json,os,pathlib,sys
x=json.load(sys.stdin); info=x.get("info",{})
if isinstance(info,str): info=json.loads(info)
st=x.get("status",{}); pid=int(info.get("pid",0))
if pid<=1 or pathlib.Path("/proc/%d/comm"%pid).read_text().strip()!="etcd":
    sys.exit("Selected running process is not etcd")
root="/proc/%d"%pid
stat=pathlib.Path(root+"/stat").read_text(); start=stat[stat.rfind(")")+2:].split()[19]
allowed={"name","advertise-client-urls","listen-client-urls","initial-advertise-peer-urls","listen-peer-urls","trusted-ca-file","cert-file","key-file","peer-trusted-ca-file","peer-cert-file","peer-key-file","client-cert-auth","peer-client-cert-auth","listen-metrics-urls"}
env={}
for item in pathlib.Path(root+"/environ").read_bytes().split(b"\0"):
    k,sep,v=item.partition(b"="); k=k.decode("utf8","replace")
    if sep and k.startswith("ETCD_") and k[5:].lower().replace("_","-") in allowed:
        env[k]=v.decode("utf8","replace")
argv=pathlib.Path(root+"/cmdline").read_bytes().decode("utf8","replace").split("\0")
flags={}
for i,arg in enumerate(argv):
    k,eq,v=arg[2:].partition("=") if arg.startswith("--") else ("","","")
    if k in allowed: flags[k]=v if eq else (argv[i+1] if i+1<len(argv) else "")
labels=st.get("labels",{})
meta={"pid":pid,"start_ticks":start,"container_id":st.get("id"),"image":st.get("image",{}).get("image"),"image_ref":st.get("imageRef"),"pod":{k:labels.get(k) for k in ["io.kubernetes.pod.name","io.kubernetes.pod.namespace"]},"env":env,"flags":flags,"netns":os.readlink(root+"/ns/net")}
try:
    fd=os.open(root+"/mem",os.O_RDONLY); os.close(fd); meta["proc_mem_open"]="permitted (no memory read)"
except OSError as e: meta["proc_mem_open"]=str(e)
pathlib.Path(sys.argv[1]).write_text(json.dumps(meta,indent=2)+"\n")
' "$work/process.json" || { echo "Inspection failed; partial report: $report" >&2; exit 2; }
read -r pid start < <(python3 -c 'import json,sys; x=json.load(open(sys.argv[1])); print(x["pid"],x["start_ticks"])' "$work/process.json")
{
  section 'Selected process'; cat "$work/process.json"
  section 'Executable'; check sha256sum "/proc/$pid/exe"
  check file -L "/proc/$pid/exe"
  check "${cri[@]}" exec "$cid" etcd --version
  section 'Peer TCP sockets (read only)'
  check nsenter -t "$pid" -n -- ss -Hntie '( sport = :2380 or dport = :2380 )'
  section 'Client TLS paths (contents excluded)'
  printf 'CA=%s\nCERT=%s\nKEY=%s\n' "$ca" "$cert" "$key"
  tls_ok=1
  for path in "$ca" "$cert" "$key"; do
    case "$path" in /*) ;; *) echo 'TLS paths must be absolute'; tls_ok=0; continue;; esac
    case "/$path/" in */../*) echo 'TLS paths must not contain ..'; tls_ok=0; continue;; esac
    if [ ! -r "/proc/$pid/root$path" ]; then echo "Missing/unreadable: $path"; tls_ok=0; fi
  done
  if [ "$tls_ok" = 1 ]; then
    section 'Client certificate metadata (no PEM/key export)'
    check openssl x509 -in "/proc/$pid/root$cert" -noout -subject -issuer -dates -ext subjectAltName
    section 'Local etcd status, membership, health'
    for cmd in status members health; do
      case "$cmd" in status) args=(endpoint status -w json);;
        members) args=(member list -w json);; health) args=(endpoint health -w json);; esac
      check "${cri[@]}" exec "$cid" etcdctl --endpoints=https://localhost:2379 \
        --cacert="$ca" --cert="$cert" --key="$key" --dial-timeout=3s --command-timeout=5s "${args[@]}"
    done
    section 'Local active-peer metrics (TLS verified)'
    # No -k; explicit proxy bypass prevents local credentials going to a proxy.
    if metrics=$(timeout 12 nsenter -t "$pid" -n -- curl --silent --show-error --fail \
      --max-time 8 --noproxy '*' --cacert "/proc/$pid/root$ca" \
      --cert "/proc/$pid/root$cert" --key "/proc/$pid/root$key" \
      https://localhost:2382/metrics); then
      printf '%s\n' "$metrics" | awk '/^# (HELP|TYPE) etcd_network_active_peers / || /^etcd_network_active_peers[ {]/'
    else echo '[metrics unavailable; listener or TLS paths may differ]'; fi
  else echo 'Authenticated diagnostics skipped; rerun with actual client TLS paths.'; fi
} >> "$report" 2>&1
# Pin the process across collection and optional export; do not label a replacement
# executable as the one inspected above.
python3 - "$pid" "$start" <<'PY'
import pathlib,sys
s=pathlib.Path('/proc/'+sys.argv[1]+'/stat').read_text()
if s[s.rfind(')')+2:].split()[19]!=sys.argv[2]: sys.exit('Process changed; rerun collector')
PY
if [ "$include" = 1 ]; then
  cp "/proc/$pid/exe" "$work/etcd-executable"
  chmod 600 "$work/etcd-executable"
  sha256sum "$work/etcd-executable" >> "$report"
fi
archive=$work.tar.gz
tar -czf "$archive" -C "$(dirname "$work")" "$(basename "$work")"
sha256sum "$archive" > "$archive.sha256"
printf 'Report: %s\nChecksum: %s\nWorking files retained: %s\n' "$archive" "$archive.sha256" "$work"
