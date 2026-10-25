"""Dry run for the spike-S4 cases of the `managed` scenario: builds each case's managed settings and checks their shape.
Writes nothing to the managed-settings location and runs no Claude Code (no sudo).

    python3 -m unittest repro/test_s4_specs.py
"""
import json
import re
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import harness


class S4Specs(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.out = Path(self.tmp.name)
        self.specs = harness.s4_specs(self.out, "http://127.0.0.1:1")

    def tearDown(self):
        self.tmp.cleanup()

    def files(self, spec):
        """Every settings file the case would write: the main file and the drop-ins."""
        return ([spec["managed_settings"]] if spec["managed_settings"] is not None else []) + list(spec.get("dropins", {}).values())

    def test_cases_exist_and_serialize(self):
        self.assertEqual(set(self.specs), {"unknownkey", "envkeys", "dropin", "dropinonly"})
        for name, spec in self.specs.items():
            for f in self.files(spec):
                json.dumps(f)

    def test_every_hook_is_guarded_and_only_records_aigw(self):
        for name, spec in self.specs.items():
            for f in self.files(spec):
                for entries in f.get("hooks", {}).values():
                    for e in entries:
                        for h in e["hooks"]:
                            self.assertTrue(h["command"].startswith(f'[ -n "${harness.Managed.MARK}" ] || exit 0; '), name)
        script = harness.S4_HOOK_SCRIPT
        self.assertIn('k.startswith("AIGW_")', script)
        self.assertNotIn("os.environ)", script.replace("os.environ.items()", ""))     # no other use of the environment

    def test_unknownkey_case(self):
        f = self.specs["unknownkey"]["managed_settings"]
        self.assertIn("aigwClaudeAuth", f)
        self.assertIn(harness.S4_MARKER, json.dumps(f["aigwClaudeAuth"]))
        self.assertEqual(f["env"], {"ANTHROPIC_BASE_URL": "http://127.0.0.1:1"})
        self.assertEqual(set(f["hooks"]), {"UserPromptSubmit", "StopFailure"})

    def test_envkeys_case(self):
        spec = self.specs["envkeys"]
        self.assertEqual(spec["managed_settings"]["env"]["AIGW_ISSUER"], "managed-issuer")
        self.assertEqual(spec["user_env"]["AIGW_ISSUER"], "user-issuer")       # the conflict
        self.assertIn("AIGW_USER_ONLY", spec["user_env"])

    def test_dropin_cases(self):
        d = self.specs["dropin"]
        self.assertEqual(sorted(d["dropins"]), ["10-a.json", "20-b.json"])
        conflicts = [f["env"]["AIGW_CONFLICT"] for f in self.files(d)]
        self.assertEqual(len(set(conflicts)), 3)                                  # set in all three files, three values
        self.assertIsNone(self.specs["dropinonly"]["managed_settings"])
        self.assertEqual(list(self.specs["dropinonly"]["dropins"]), ["10-only.json"])

    def test_dummy_values_only(self):
        text = json.dumps(self.specs)
        self.assertNotRegex(text, r"eyJ|sk-ant|Bearer ")
        for name, spec in self.specs.items():
            for f in self.files(spec):
                for k in f.get("env", {}):
                    self.assertTrue(k == "ANTHROPIC_BASE_URL" or k.startswith("AIGW_"), k)

    def test_bash_command_reads_only_aigw(self):
        cmd = harness.s4_bash_command(self.out)
        self.assertTrue(cmd.startswith("env | grep '^AIGW_'"))
        self.assertIn("bash.env", cmd)


class ManagedWrites(unittest.TestCase):
    """Managed.write/clear with `sudo` replaced by a recorder: which paths they touch."""

    def test_paths(self):
        calls = []
        with tempfile.TemporaryDirectory() as tmp:
            m = harness.Managed.__new__(harness.Managed)
            m.out, m.file, m.dropin = Path(tmp), Path("/managed/managed-settings.json"), Path("/managed/managed-settings.d")
            m.dropin_files, m.made_dropin = [], False
            m.sudo = lambda *a: calls.append(a)
            m.write(None, {"10-x.json": {"env": {}}})
            m.clear()
        verbs = [c[0] for c in calls]
        self.assertEqual(verbs, ["mkdir", "install", "rm", "rm", "rmdir"])
        self.assertEqual(calls[-1][-1], "/managed/managed-settings.d")
        self.assertEqual(calls[3][-1], "/managed/managed-settings.d/10-x.json")


class MockBashTurn(unittest.TestCase):
    def post(self, gw, messages):
        import urllib.request
        body = json.dumps({"model": "m", "stream": True, "tools": [{"name": "Bash"}], "messages": messages}).encode()
        req = urllib.request.Request(gw.url + "/v1/messages", data=body, headers={"x-portkey-api-key": harness.fresh_jwt(), "authorization": f"Bearer {harness.OAUTH}"})
        return urllib.request.urlopen(req, timeout=10).read().decode()

    def test_tool_use_only_for_the_trigger_prompt(self):
        with tempfile.TemporaryDirectory() as tmp:
            gw = harness.Gateway(Path(tmp), bash_command="echo hi")
            try:
                ask = [{"role": "user", "content": [{"type": "text", "text": "RUN-BASH please"}]}]
                self.assertIn('"type": "tool_use"', self.post(gw, ask))
                done = ask + [{"role": "assistant", "content": []}, {"role": "user", "content": [{"type": "tool_result", "content": "RUN-BASH"}]}]
                self.assertIn("MOCK-OK", self.post(gw, done))
                self.assertIn("MOCK-OK", self.post(gw, [{"role": "user", "content": "hello"}]))
            finally:
                gw.close()


if __name__ == "__main__":
    unittest.main()
