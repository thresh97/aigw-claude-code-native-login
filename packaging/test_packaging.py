#!/usr/bin/env python3
"""Offline tests for the fleet packaging (python3 -m unittest -v packaging/test_packaging.py). Throwaway dirs only.

Covers the generator (managed settings, config, background-start definitions per OS), the per-user launcher, and, where the
tools exist on this machine, a macOS pkg build plus a DESTDIR dry run of its scripts. The Docker and Windows checks are
scripts (packaging/linux/container-test-*.sh, packaging/windows/*.ps1) run by hand; see packaging/README.md.
"""
import base64
import copy
import json
import os
import plistlib
import shutil
import subprocess
import sys
import tempfile
import time
import unittest
import xml.etree.ElementTree as ET
from pathlib import Path
from unittest import mock

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import build           # noqa: E402
import aigw_launch    # noqa: E402

CLIENT = build.load_client()
EXAMPLE = HERE / "fleet.example.json"


def fleet(**over):
    f = build.load_fleet(EXAMPLE)
    f.update(over)
    return f


def fake_jwt(seconds=3600):
    def b64(d):
        return base64.urlsafe_b64encode(json.dumps(d).encode()).decode().rstrip("=")
    return f"{b64({'alg': 'none'})}.{b64({'exp': int(time.time()) + seconds, 'iss': 'x'})}.sig"


class Generator(unittest.TestCase):
    def test_example_is_placeholders_only(self):
        f = json.loads(EXAMPLE.read_text())
        found = build.find_placeholders(f)
        self.assertIn("gateway_url", found)
        self.assertIn("idp.issuer", found)
        self.assertIn("idp.client_id", found)
        text = EXAMPLE.read_text()
        self.assertNotRegex(text, r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b(?<!127\.0\.0\.1)(?!:)")

    def test_real_build_refuses_placeholders(self):
        with tempfile.TemporaryDirectory() as d, mock.patch("sys.stderr"):
            self.assertEqual(build.main(["macos", "--fleet", str(EXAMPLE), "--out", d]), 1)
            self.assertEqual(build.main(["linux", "--fleet", str(EXAMPLE), "--out", d]), 1)
            self.assertEqual(build.main(["windows", "--fleet", str(EXAMPLE), "--out", d]), 1)

    def test_unknown_keys_refused(self):
        with tempfile.TemporaryDirectory() as d:
            p = Path(d) / "f.json"
            for bad in ({"nope": 1}, {"options": {"nope": 1}}):
                data = json.loads(EXAMPLE.read_text())
                data.update(bad)
                p.write_text(json.dumps(data))
                with self.assertRaises(build.BuildError):
                    build.load_fleet(p)

    def test_client_refuses_bad_profile(self):
        f = fleet(idp={"client_id": "x", "login_method": "carrier-pigeon"})
        with self.assertRaises(build.BuildError):
            build.render(f, "linux")

    def test_file_mode_managed_settings(self):
        for osname in ("macos", "linux", "windows"):
            with self.subTest(os=osname):
                f = fleet()
                files, paths = build.render(f, osname)
                m = json.loads(files["managed"])
                cfg = json.loads(files["config"])
                self.assertNotIn("ANTHROPIC_CUSTOM_HEADERS", m["env"])        # finding 11
                self.assertNotIn("ANTHROPIC_CUSTOM_HEADERS", json.dumps(m))
                self.assertEqual(m["env"]["ANTHROPIC_BASE_URL"], f["gateway_url"])
                self.assertEqual(m["allowedProviders"], ["customEndpoint"])
                self.assertNotIn("gateway_url", cfg)                          # one place for the URL in file mode
                # AIGW_* in managed env equal the config values as strings (what doctor's managed-config-conflict compares)
                for k, v in m["env"].items():
                    if k.startswith("AIGW_"):
                        self.assertEqual(str(cfg[k[5:].lower()]), v)
                self.assertEqual(m["env"]["AIGW_MODE"], "file")
                # hooks are exactly what the client's hook_entry makes for this command
                cmd = build.hook_command(osname, paths, f)
                self.assertEqual(m["hooks"]["UserPromptSubmit"], [CLIENT.hook_entry(cmd, "precheck")])
                self.assertEqual(m["hooks"]["StopFailure"], [CLIENT.hook_entry(cmd, "stop-failure")])
                self.assertTrue(CLIENT.MARKER.search(json.dumps(m["hooks"])))   # install/doctor find the entries by this
                self.assertEqual(m["hooks"]["UserPromptSubmit"][0]["hooks"][0]["timeout"], CLIENT.HOOK_TIMEOUT)

    def test_hook_form_per_os(self):
        for osname, exec_form in (("macos", False), ("linux", False), ("windows", True)):
            f = fleet()
            files, paths = build.render(f, osname)
            h = json.loads(files["managed"])["hooks"]["UserPromptSubmit"][0]["hooks"][0]
            self.assertEqual("args" in h, exec_form)       # Windows: exec form, no shell (finding 17)
            self.assertIn(paths["config"], h["args"] if exec_form else h["command"])

    def test_matches_install_print(self):
        """The managed hooks equal `install --print` for the same hook command."""
        f = fleet()
        files, paths = build.render(f, "linux")
        cmd = build.hook_command("linux", paths, f)
        with tempfile.TemporaryDirectory() as d, mock.patch.dict(os.environ, {"HOME": d, "AIGW_CLAUDE_AUTH_DIR": d}):
            cfgp = Path(d) / "config.json"
            cfgp.write_bytes(files["config"])
            out = subprocess.run([sys.executable, str(build.CLIENT_PATH), "--config", str(cfgp), "install", "--print",
                                  "--base-url", f["gateway_url"], "--hook-command", cmd], capture_output=True, text=True)
        self.assertEqual(out.returncode, 0, out.stderr)
        printed = json.loads(out.stdout)
        m = json.loads(files["managed"])
        self.assertEqual(printed["hooks"], m["hooks"])
        self.assertEqual(printed["env"]["ANTHROPIC_BASE_URL"], m["env"]["ANTHROPIC_BASE_URL"])

    def test_proxy_mode(self):
        f = fleet(mode="proxy", proxy_listen="127.0.0.1:18999")
        for osname in ("macos", "linux", "windows"):
            files, _ = build.render(f, osname)
            m, cfg = json.loads(files["managed"]), json.loads(files["config"])
            self.assertEqual(m["env"]["ANTHROPIC_BASE_URL"], "http://127.0.0.1:18999")
            self.assertEqual(m["env"]["ANTHROPIC_BASE_URL"], CLIENT.proxy_base_url(dict(CLIENT.DEFAULTS, **cfg)))
            self.assertEqual(cfg["gateway_url"], f["gateway_url"])
            self.assertNotIn("ANTHROPIC_CUSTOM_HEADERS", json.dumps(m))      # the per-user secret is written per user
            self.assertEqual(m["env"]["AIGW_MODE"], "proxy")

    def test_proxy_needs_fixed_loopback_port(self):
        for listen in ("127.0.0.1:0", "0.0.0.0:18787"):
            with self.assertRaises((build.BuildError, CLIENT.AuthError)):
                build.render(fleet(mode="proxy", proxy_listen=listen), "linux")

    def test_options(self):
        files, _ = build.render(fleet(options={"pin_allowed_providers": False, "allow_managed_hooks_only": True, "notify": "off"}), "linux")
        m, cfg = json.loads(files["managed"]), json.loads(files["config"])
        self.assertNotIn("allowedProviders", m)
        self.assertTrue(m["allowManagedHooksOnly"])
        self.assertEqual(cfg["notify"], "off")

    def test_background_start_definitions(self):
        f = fleet()
        files, paths = build.render(f, "macos")
        pl = plistlib.loads(files["bgstart"])
        self.assertEqual(pl["ProgramArguments"], ["/usr/bin/python3", paths["launcher"], "daemon"])
        self.assertTrue(pl["RunAtLoad"])
        self.assertTrue(paths["bgstart"].startswith("/Library/LaunchAgents/"))
        files, paths = build.render(f, "linux")
        unit = files["bgstart"].decode()
        self.assertIn(f"ExecStart=/usr/bin/python3 {paths['launcher']} daemon", unit)
        self.assertIn("WantedBy=default.target", unit)
        self.assertTrue(paths["bgstart"].startswith("/usr/lib/systemd/user/"))

    def test_windows_task_is_the_clients_xml_for_the_users_group(self):
        files, paths = build.render(fleet(), "windows")
        xml = files["bgstart"].decode("utf-16")
        root = ET.fromstring(xml.split("?>", 1)[1])
        ns = {"t": "http://schemas.microsoft.com/windows/2004/02/mit/task"}
        self.assertEqual(root.find("t:Principals/t:Principal/t:GroupId", ns).text, "S-1-5-32-545")
        self.assertIsNone(root.find("t:Triggers/t:LogonTrigger/t:UserId", ns))
        self.assertTrue(root.find("t:Actions/t:Exec/t:Command", ns).text.endswith("pythonw.exe"))
        self.assertIn("aigw_launch.py", root.find("t:Actions/t:Exec/t:Arguments", ns).text)
        self.assertNotIn("__USER__", xml)
        # everything else is the client's definition: one instance, restart on failure, no time limit
        self.assertEqual(root.find("t:Settings/t:MultipleInstancesPolicy", ns).text, "IgnoreNew")
        self.assertIsNotNone(root.find("t:Settings/t:RestartOnFailure", ns))

    def test_installed_layout_is_consistent(self):
        for osname in ("macos", "linux", "windows"):
            files, paths = build.render(fleet(), osname)
            self.assertEqual(set(files), {"client", "launcher", "config", "managed", "bgstart"})
            sep = "\\" if osname == "windows" else "/"
            for role in ("client", "launcher", "config"):
                self.assertTrue(paths[role].startswith(paths["install_dir"] + sep))
            self.assertTrue(paths["managed"].endswith("managed-settings.d" + sep + "50-aigw-claude-auth.json"))
        self.assertEqual(files["client"], build.CLIENT_PATH.read_bytes())       # the client is copied as is


class Launcher(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        t = Path(self.tmp.name)
        self.fleet_dir, self.home = t / "lib", t / "home"
        self.fleet_dir.mkdir()
        self.home.mkdir()
        shutil.copy(build.CLIENT_PATH, self.fleet_dir)
        self.jwt_file = t / "jwt"
        self.jwt_file.write_text(fake_jwt())
        env = {"HOME": str(self.home), "USERPROFILE": str(self.home), "AIGW_CLAUDE_AUTH_DIR": str(self.home / "cfg"),
               "AIGW_CLAUDE_SETTINGS": str(self.home / ".claude" / "settings.json"), "AIGW_FLEET_DIR": str(self.fleet_dir)}
        p = mock.patch.dict(os.environ, env)
        p.start()
        self.addCleanup(p.stop)
        self.settings = self.home / ".claude" / "settings.json"

    def config(self, **over):
        cfg = {"token_command": f"{shlex_quote(sys.executable)} -c \"print(open(r'{self.jwt_file}').read())\"",
               "secret_store": "file", "notify": "off", "hook_login": "off"}
        cfg.update(over)
        (self.fleet_dir / "config.json").write_text(json.dumps(cfg))

    def run_launcher(self):
        """The launcher's main, with the daemon replaced by a recorder (the real one never returns)."""
        calls = []
        with mock.patch.object(aigw_launch, "HERE", str(self.fleet_dir)):
            real = aigw_launch.load_client()

        class Wrapped:
            def __getattr__(self, n):
                return getattr(real, n)

            @staticmethod
            def main(argv):
                calls.append(argv[2:])
                return 0 if argv[2] == "daemon" else real.main(argv)
        with mock.patch.object(aigw_launch, "HERE", str(self.fleet_dir)), mock.patch.object(aigw_launch, "load_client", lambda: Wrapped()), \
                mock.patch("sys.stderr"):
            rc = aigw_launch.main([])
        return rc, calls

    def test_first_run_file_mode(self):
        self.config()
        rc, calls = self.run_launcher()
        self.assertEqual(calls, [["install", "--no-hooks"], ["daemon"]])       # install first, then the daemon
        s = json.loads(self.settings.read_text())
        self.assertNotIn("hooks", s)                                           # the hooks come from managed settings
        self.assertIn("x-portkey-api-key", s["env"]["ANTHROPIC_CUSTOM_HEADERS"])
        self.assertNotIn("ANTHROPIC_BASE_URL", s["env"])                       # managed settings carry the URL

    def test_first_run_proxy_mode_writes_a_per_user_secret(self):
        self.config(mode="proxy", gateway_url="https://gw.example.invalid", proxy_listen="127.0.0.1:18999")
        self.run_launcher()
        s1 = json.loads(self.settings.read_text())
        self.assertEqual(s1["env"]["ANTHROPIC_BASE_URL"], "http://127.0.0.1:18999")
        lines = s1["env"]["ANTHROPIC_CUSTOM_HEADERS"]
        self.assertIn("x-aigw-local", lines)
        self.assertNotIn("x-portkey-api-key", lines)                            # no JWT on disk in proxy mode
        self.run_launcher()                                                     # idempotent: same secret on the next login
        self.assertEqual(json.loads(self.settings.read_text())["env"]["ANTHROPIC_CUSTOM_HEADERS"], lines)
        # a second user gets a different secret
        other = Path(self.tmp.name) / "home2"
        with mock.patch.dict(os.environ, {"AIGW_CLAUDE_AUTH_DIR": str(other / "cfg"), "AIGW_CLAUDE_SETTINGS": str(other / "s.json")}):
            self.run_launcher()
            self.assertNotEqual(json.loads((other / "s.json").read_text())["env"]["ANTHROPIC_CUSTOM_HEADERS"], lines)

    def test_broken_first_run_still_starts_the_daemon(self):
        self.config(mode="nonsense")
        rc, calls = self.run_launcher()
        self.assertEqual(calls[-1], ["daemon"])

    def test_purge_user(self):
        self.config(mode="proxy", gateway_url="https://gw.example.invalid", proxy_listen="127.0.0.1:18999")
        self.run_launcher()
        self.assertTrue((self.home / "cfg").exists())
        with mock.patch.object(aigw_launch, "HERE", str(self.fleet_dir)), mock.patch("sys.stderr"):
            self.assertEqual(aigw_launch.main(["purge-user"]), 0)
        s = json.loads(self.settings.read_text())
        self.assertNotIn("ANTHROPIC_CUSTOM_HEADERS", s.get("env", {}))
        self.assertNotIn("ANTHROPIC_BASE_URL", s.get("env", {}))
        self.assertFalse((self.home / "cfg").exists())

    def test_purge_user_removes_the_windows_log_folder(self):
        self.config()
        logs = self.home / "AppData" / "Local" / "aigw-claude-auth" / "logs"
        logs.mkdir(parents=True)
        (logs / "daemon.log").write_text("x")
        with mock.patch.object(aigw_launch, "HERE", str(self.fleet_dir)):
            real = aigw_launch.load_client()
        main = real.main

        def main_then_windows(argv):            # the client's own code runs as on this OS; only the launcher's cleanup sees Windows
            rc = main(argv)
            real.is_windows = lambda: True
            return rc
        real.main = main_then_windows
        with mock.patch.object(aigw_launch, "HERE", str(self.fleet_dir)), mock.patch.object(aigw_launch, "load_client", lambda: real), \
                mock.patch.dict(os.environ, {"LOCALAPPDATA": str(self.home / "AppData" / "Local")}), mock.patch("sys.stderr"):
            self.assertEqual(aigw_launch.main(["purge-user"]), 0)
        self.assertFalse(logs.parent.exists())


def shlex_quote(s):
    import shlex
    return shlex.quote(s)


@unittest.skipUnless(sys.platform == "darwin" and shutil.which("pkgbuild") and shutil.which("productbuild") and shutil.which("pkgutil"),
                     "needs macOS pkgbuild/productbuild/pkgutil")
class MacPkg(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory()
        cls.out = Path(cls.tmp.name)
        with mock.patch("sys.stderr"):
            cls.pkg = build.build_macos(fleet(), cls.out)

    @classmethod
    def tearDownClass(cls):
        cls.tmp.cleanup()

    def test_payload(self):
        files = subprocess.run(["pkgutil", "--payload-files", str(self.pkg)], capture_output=True, text=True, check=True).stdout.split("\n")
        for want in ("./usr/local/libexec/aigw-claude-auth/aigw_claude_auth.py", "./usr/local/libexec/aigw-claude-auth/config.json",
                     "./usr/local/libexec/aigw-claude-auth/uninstall.sh",
                     "./Library/Application Support/ClaudeCode/managed-settings.d/50-aigw-claude-auth.json",
                     "./Library/LaunchAgents/aigw-claude-auth.fleet.plist"):
            self.assertIn(want, files)
        self.assertNotIn("./Library/Application Support/ClaudeCode/managed-settings.json", files)     # never clobbers the main file

    def test_plist_lints(self):
        p = self.out / "macos-work" / "root" / "Library" / "LaunchAgents" / "aigw-claude-auth.fleet.plist"
        self.assertEqual(subprocess.run(["plutil", "-lint", str(p)], capture_output=True).returncode, 0)

    def test_scripts_dry_run_with_destdir(self):
        dest = self.out / "dry"
        shutil.copytree(self.out / "macos-work" / "root", dest)
        env = dict(os.environ, DESTDIR=str(dest))
        post = self.out / "macos-work" / "scripts" / "postinstall"
        self.assertEqual(subprocess.run(["sh", str(post)], env=env, capture_output=True).returncode, 0)
        un = dest / "usr/local/libexec/aigw-claude-auth/uninstall.sh"
        self.assertTrue(os.access(un, os.X_OK))
        self.assertEqual(subprocess.run(["sh", str(un)], env=env, capture_output=True).returncode, 0)
        self.assertEqual([p for p in dest.rglob("*") if p.is_file()], [])       # everything the package put there is gone

    def test_destdir_postinstall_keeps_other_managed_files(self):
        dest = self.out / "dry2"
        shutil.copytree(self.out / "macos-work" / "root", dest)
        other = dest / "Library/Application Support/ClaudeCode/managed-settings.d/10-other.json"
        other.write_text("{}")
        env = dict(os.environ, DESTDIR=str(dest))
        un = dest / "usr/local/libexec/aigw-claude-auth/uninstall.sh"
        subprocess.run(["sh", str(un)], env=env, capture_output=True, check=True)
        self.assertTrue(other.exists())


class WindowsPayload(unittest.TestCase):
    def test_build_windows(self):
        with tempfile.TemporaryDirectory() as d:
            dest = build.build_windows(fleet(), Path(d))
            names = sorted(p.name for p in dest.rglob("*") if p.is_file())
            self.assertEqual(names, sorted(["50-aigw-claude-auth.json", "Install-AigwClaudeAuth.ps1", "Uninstall-AigwClaudeAuth.ps1",
                                            "aigw_claude_auth.py", "aigw_launch.py", "config.json", "fleet.txt", "task.xml"]))
            for ps in dest.glob("*.ps1"):
                text = ps.read_bytes()
                text.decode("ascii")                      # Windows PowerShell 5.1 reads BOM-less files as ANSI: keep them ASCII
                self.assertIn(b"SupportsShouldProcess", text)
                # `powershell -File` (Intune, ssh) evaluates param defaults before $PSScriptRoot is set (PS 5.1)
                param_block = text.decode().split("param(", 1)[1].split("\n)", 1)[0]
                self.assertNotIn("$PSScriptRoot", param_block, ps.name)


if __name__ == "__main__":
    unittest.main()
