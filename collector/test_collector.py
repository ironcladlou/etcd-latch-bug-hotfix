"""Local, nonprivileged checks for the Python embedded in the shell collector."""
import contextlib
import hashlib
import io
import json
import pathlib
import subprocess
import tarfile
import tempfile
import types
import unittest
from unittest import mock

source = pathlib.Path(__file__).with_name("collect-etcd-host.sh").read_text()
collector = types.ModuleType("collector")
exec(compile(source.split("<<'PYTHON'\n", 1)[1].rsplit("\nPYTHON", 1)[0],
             "collect-etcd-host.sh", "exec"), collector.__dict__)


class CollectorTests(unittest.TestCase):
    def test_json_keeps_uint64_member_ids_exact(self):
        ident = 18446744073709551614
        result = collector.json_result(dict(status="ok", stdout=json.dumps({"ID": ident}), stderr="", exit_code=0))
        self.assertEqual(result["data"]["ID"], ident)
        self.assertNotIn("stdout", result)

    def test_malformed_json_is_an_explicit_failure(self):
        result = collector.json_result(dict(status="ok", stdout="broken", stderr="", exit_code=0))
        self.assertEqual(result["status"], "invalid_json")
        self.assertEqual(result["stdout"], "broken")

    def test_metrics_are_typed_and_unrelated_metrics_excluded(self):
        raw = '# HELP etcd_network_active_peers Active peers\n'
        raw += 'etcd_network_active_peers{Local="aa",Remote="bb"} 0\n'
        raw += 'unrelated_secret_metric{value="do-not-export"} 1\n'
        result = collector.active_peers(dict(status="ok", stdout=raw, stderr="", exit_code=0))
        self.assertEqual(result["samples"], [{"labels": {"Local": "aa", "Remote": "bb"}, "value": 0}])
        self.assertNotIn("do-not-export", json.dumps(result))
        self.assertNotIn("stdout", result)
        result = collector.active_peers(dict(status="ok", stdout="", stderr="", exit_code=0))
        self.assertEqual(result["status"], "missing_metric")

    def test_unavailable_command_and_timeout_are_structured(self):
        with mock.patch.object(collector.subprocess, "run", side_effect=FileNotFoundError("missing")):
            self.assertEqual(collector.command(["missing"])["status"], "unavailable")
        error = subprocess.TimeoutExpired(["cmd"], 20, output=b"partial", stderr=b"problem")
        with mock.patch.object(collector.subprocess, "run", side_effect=error):
            result = collector.command(["cmd"])
        self.assertEqual((result["status"], result["stdout"], result["stderr"]), ("timeout", "partial", "problem"))

    def test_cri_failures_do_not_export_raw_responses(self):
        for result in [dict(status="failed", stdout="SECRET", stderr="SECRET", exit_code=1),
                       dict(status="ok", stdout="SECRET", stderr="", exit_code=0)]:
            with mock.patch.object(collector, "command", return_value=result):
                with self.assertRaises(RuntimeError) as caught:
                    collector.cri_json(["crictl", "inspect"])
                self.assertNotIn("SECRET", str(caught.exception))

    def test_process_metadata_filters_environment_flags_and_cri(self):
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            (root / "comm").write_text("etcd\n")
            (root / "environ").write_bytes(b"ETCD_NAME=etcd-1\0TOKEN=SECRET\0ETCD_PASSWORD=SECRET\0")
            (root / "cmdline").write_bytes(b"etcd\0--cert-file=/cert.crt\0--password=SECRET\0")
            detail = {"info": {"pid": 123, "runtimeSpec": "SECRET"}, "status": {
                "id": "abc", "image": {"image": "example/image", "annotations": {"secret": "SECRET"}},
                "labels": {"unrelated": "SECRET"}}}
            with mock.patch.object(collector.pathlib, "Path", return_value=root), \
                 mock.patch.object(collector, "start_ticks", return_value="100"), \
                 mock.patch.object(collector.os, "readlink", return_value="net:[123]"), \
                 mock.patch.object(collector.os, "open", side_effect=PermissionError("denied")):
                meta = collector.process_metadata(detail)
            self.assertEqual(meta["env"], {"ETCD_NAME": "etcd-1"})
            self.assertEqual(meta["flags"], {"cert-file": "/cert.crt"})
            self.assertNotIn("SECRET", json.dumps(meta))
            self.assertEqual(meta["proc_mem_open"]["status"], "failed")

    def run_main(self, collect):
        with tempfile.TemporaryDirectory() as directory:
            stdout = io.StringIO()
            with mock.patch.object(collector.sys, "argv", ["collector", "--output-dir", directory]), \
                 mock.patch.object(collector.sys, "platform", "linux"), \
                 mock.patch.object(collector.os, "geteuid", return_value=0), \
                 mock.patch.object(collector, "collect", side_effect=collect), \
                 contextlib.redirect_stdout(stdout):
                code = collector.main()
            report = json.loads(stdout.getvalue())
            archive = pathlib.Path(report["artifacts"]["archive"])
            with tarfile.open(str(archive)) as tar:
                self.assertEqual(len(tar.getnames()), 1)
                self.assertEqual(json.load(tar.extractfile(tar.getnames()[0])), report)
            self.assertEqual(json.loads(pathlib.Path(report["artifacts"]["report"]).read_text()), report)
            self.assertEqual(pathlib.Path(report["artifacts"]["checksum"]).read_text().split()[0],
                             hashlib.sha256(archive.read_bytes()).hexdigest())
            return code, report

    def test_stdout_file_and_archive_contain_same_json(self):
        def collect(args, report, work):
            report["checks"]["optional"] = {"status": "unavailable", "error": "missing"}
        code, report = self.run_main(collect)
        self.assertEqual((code, report["collection_status"]), (0, "completed"))

    def test_partial_report_is_packaged_on_selection_failure(self):
        def collect(args, report, work):
            raise RuntimeError("select --container ID")
        code, report = self.run_main(collect)
        self.assertEqual((code, report["collection_status"]), (2, "failed"))
        self.assertEqual(report["error"], "select --container ID")


if __name__ == "__main__":
    unittest.main(verbosity=2)
