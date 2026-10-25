#!/usr/bin/env python3
"""Spike S7 probe: native Windows and Claude Code (hook shell and quoting, settings file locking, toast from a hook).

Usage:   py -3 repro\\winprobe.py --out DIR [--only basics,hooks,lock,toast] [--ask]     (Windows)
         python3 repro/winprobe.py --out DIR                                           (macOS/Linux: Windows-only parts `skipped`)

Output on stdout: one `key=value` line per observation, like harness.py (plus a few `ACTION:` lines for the person
running it). Details (hook dumps, raw hook events, request logs with credential fingerprints, Claude Code's output) go to
DIR. Dummy credentials only; the hook scripts record argv, a few named environment variables and the process ancestry,
never the environment.

Phases (--only, default basics,hooks,lock,toast):
  basics       Windows, Python, Claude Code, Git for Windows, PowerShell versions
  hooks        S7.1: which shell runs a hook command, and what argv each command form delivers
  lock         S7.2: os.replace over settings.json (the client's write_private) while a session makes requests
  toast        S7.3: a WinRT toast from a hook through powershell.exe -EncodedCommand
  interactive  S7.2 with the real TUI: opt-in, you type prompts while the probe replaces the file (not in the default set)

Everything runs in a throwaway HOME/USERPROFILE/APPDATA/CLAUDE_CONFIG_DIR under DIR, against the mock gateway on
127.0.0.1. The probe reuses harness.py (Gateway, Claude) and the client's write_private. harness.py imports the client's
tests, which import the client, which imports fcntl; fcntl does not exist on Windows, so an empty stand-in module is
registered first (the client only uses it in lock(), which the probe never calls).
"""
import argparse
import json
import os
import platform
import shutil
import subprocess
import sys
import tempfile
import threading
import time
import types
from pathlib import Path

HERE = Path(__file__).resolve().parent
try:
    import fcntl  # noqa: F401
except ImportError:                                  # Windows
    sys.modules["fcntl"] = types.ModuleType("fcntl")
sys.path[:0] = [str(HERE)]
import harness  # noqa: E402
import mock_gateway  # noqa: E402
from harness import PK, OAUTH, Claude, Gateway, fresh_jwt, observe, wait_until  # noqa: E402
import aigw_claude_auth as client_mod  # noqa: E402  (harness put client/ on sys.path)

IS_WIN = sys.platform == "win32"
PROBE_VAR = "WINPROBE_VAR"
PROBE_VALUE = "probe-value"
HOOK_TIMEOUT = 60                  # the matrix hooks; the toast hook uses the client's 30 s
CLAUDE_HAS_HOOK_EVENTS = False


def one_line(value, limit=300):
    return " ".join(str(value).split())[:limit]


# ----------------------------------------------------------------------- process helpers (shared with the hook scripts)
HELPERS = r'''
import ctypes, subprocess, sys
IS_WIN = sys.platform == "win32"


def process_table():
    """{pid: (ppid, exe name)}; Toolhelp snapshot on Windows, `ps` elsewhere."""
    table = {}
    if IS_WIN:
        from ctypes import wintypes

        class PE(ctypes.Structure):
            _fields_ = [("dwSize", wintypes.DWORD), ("cntUsage", wintypes.DWORD), ("th32ProcessID", wintypes.DWORD),
                        ("th32DefaultHeapID", ctypes.c_size_t), ("th32ModuleID", wintypes.DWORD), ("cntThreads", wintypes.DWORD),
                        ("th32ParentProcessID", wintypes.DWORD), ("pcPriClassBase", ctypes.c_long), ("dwFlags", wintypes.DWORD),
                        ("szExeFile", ctypes.c_wchar * 260)]
        k = ctypes.WinDLL("kernel32", use_last_error=True)
        k.CreateToolhelp32Snapshot.restype = wintypes.HANDLE
        k.CreateToolhelp32Snapshot.argtypes = [wintypes.DWORD, wintypes.DWORD]
        k.Process32FirstW.argtypes = k.Process32NextW.argtypes = [wintypes.HANDLE, ctypes.POINTER(PE)]
        k.CloseHandle.argtypes = [wintypes.HANDLE]
        snap = k.CreateToolhelp32Snapshot(2, 0)       # TH32CS_SNAPPROCESS
        pe = PE()
        pe.dwSize = ctypes.sizeof(PE)
        ok = k.Process32FirstW(snap, ctypes.byref(pe))
        while ok:
            table[pe.th32ProcessID] = (pe.th32ParentProcessID, pe.szExeFile)
            ok = k.Process32NextW(snap, ctypes.byref(pe))
        k.CloseHandle(snap)
    else:
        out = subprocess.run(["ps", "-axo", "pid=,ppid=,comm="], capture_output=True, text=True, timeout=10).stdout
        for line in out.splitlines():
            parts = line.split(None, 2)
            if len(parts) == 3 and parts[0].isdigit() and parts[1].isdigit():
                table[int(parts[0])] = (int(parts[1]), parts[2].rsplit("/", 1)[-1])
    return table


def ancestors(depth=6):
    """Names of this process's parents, nearest first, as ['name(pid)', ...]."""
    import os
    table, pid, out = process_table(), os.getpid(), []
    for _ in range(depth):
        pid = table.get(pid, (0, ""))[0]
        if not pid or pid not in table:
            break
        out.append(f"{table[pid][1]}({pid})")
    return out
'''
helpers = types.SimpleNamespace()
exec(compile(HELPERS, "winprobe-helpers", "exec"), helpers.__dict__)


# ----------------------------------------------------------------------- the hook scripts it writes
HOOK_DUMP = HELPERS + r'''
import json, os, subprocess, sys, time
from pathlib import Path

OUT = Path(__file__).resolve().parent / "dumps"
ENV_NAMES = ["ComSpec", "SHELL", "MSYSTEM", "MSYS", "OSTYPE", "TERM", "SHLVL", "_", "POWERSHELL_DISTRIBUTION_CHANNEL",
             "WSL_DISTRO_NAME", "CLAUDECODE", "CLAUDE_CODE_ENTRYPOINT", "CLAUDE_CODE_GIT_BASH_PATH", "WINPROBE_VAR"]


def main():
    label = next((a[5:] for a in sys.argv[1:] if a.startswith("case=")), "unknown")
    d = {"label": label, "t": time.time(), "argv": sys.argv[1:], "executable": sys.executable, "cwd": os.getcwd(),
         "env": {n: os.environ.get(n) for n in ENV_NAMES},
         "env_present": {n: n in os.environ for n in ("PSModulePath", "BASH_VERSION", "PROMPT", "PWD", "OLDPWD")},
         "psmodulepath_has_windowspowershell": "WindowsPowerShell" in os.environ.get("PSModulePath", "")}
    try:
        d["stdin_keys"] = sorted(json.loads(sys.stdin.read() or "{}"))
    except Exception as e:
        d["stdin_keys"] = f"unreadable: {type(e).__name__}"
    try:
        d["ancestors"] = ancestors()
    except Exception as e:
        d["ancestors"] = f"error: {type(e).__name__}: {e}"
    if IS_WIN:
        try:
            k = ctypes.WinDLL("kernel32")
            k.GetCommandLineW.restype = ctypes.c_wchar_p
            d["raw_cmdline"] = k.GetCommandLineW()
        except Exception as e:
            d["raw_cmdline"] = f"error: {e}"
        if label == "dq":                      # one full look at how the shell was started
            try:
                ppid = os.getppid()
                p = subprocess.run(["powershell.exe", "-NoProfile", "-NonInteractive", "-Command",
                                    f"(Get-CimInstance Win32_Process -Filter 'ProcessId={ppid}').CommandLine"],
                                   capture_output=True, text=True, timeout=20)
                d["parent_cmdline"] = p.stdout.strip()
            except Exception as e:
                d["parent_cmdline"] = f"error: {type(e).__name__}"
    OUT.mkdir(exist_ok=True)
    tmp = OUT / f".{label}.tmp"
    tmp.write_text(json.dumps(d, indent=1), encoding="utf-8")
    os.replace(tmp, OUT / f"{label}.json")


main()
'''

HOOK_TOAST = r'''
import base64, json, subprocess, sys, time
from pathlib import Path

OUT = Path(__file__).resolve().parent / "dumps"
DIRECT = "direct" in sys.argv[1:]
PS = r"""
$ErrorActionPreference = 'Stop'
try {
  Write-Output ('LanguageMode=' + $ExecutionContext.SessionState.LanguageMode)
  Write-Output ('PSVersion=' + $PSVersionTable.PSVersion)
  [Windows.UI.Notifications.ToastNotificationManager, Windows.UI.Notifications, ContentType = WindowsRuntime] | Out-Null
  [Windows.Data.Xml.Dom.XmlDocument, Windows.Data.Xml.Dom.XmlDocument, ContentType = WindowsRuntime] | Out-Null
  $xml = New-Object Windows.Data.Xml.Dom.XmlDocument
  $xml.LoadXml('<toast><visual><binding template="ToastGeneric"><text>Claude Code (winprobe)</text><text>@@TEXT@@</text></binding></visual></toast>')
  $toast = New-Object Windows.UI.Notifications.ToastNotification $xml
  [Windows.UI.Notifications.ToastNotificationManager]::CreateToastNotifier('@@AUMID@@').Show($toast)
  Write-Output 'shown'
} catch {
  [Console]::Error.WriteLine($_.Exception.GetType().Name + ': ' + $_.Exception.Message)
  exit 1
}
"""
VARIANTS = [("ps_aumid", r"{1AC14E77-02E7-4E5D-B744-2EB1AE5198B7}\WindowsPowerShell\v1.0\powershell.exe"),
            ("own_aumid", "AiGwClaudeAuth.Probe")]


def main():
    t_all, res = time.time(), {}
    for name, aumid in VARIANTS:
        text = f"toast {name} ({'direct run' if DIRECT else 'from a hook'})"
        script = PS.replace("@@AUMID@@", aumid).replace("@@TEXT@@", text)
        enc = base64.b64encode(script.encode("utf-16-le")).decode()
        cmd = ["powershell.exe", "-NoProfile", "-NonInteractive", "-WindowStyle", "Hidden", "-ExecutionPolicy", "Bypass", "-EncodedCommand", enc]
        t0 = time.time()
        try:
            p = subprocess.run(cmd, capture_output=True, text=True, timeout=12, stdin=subprocess.DEVNULL,
                               creationflags=0x08000000)      # CREATE_NO_WINDOW
            r = {"exit": p.returncode, "stdout": p.stdout.strip()[:300], "stderr": p.stderr.strip()[:500]}
        except Exception as e:
            r = {"exit": None, "error": f"{type(e).__name__}: {e}"[:300]}
        r["seconds"] = round(time.time() - t0, 2)
        r["text"] = text
        res[name] = r
    res["total_seconds"] = round(time.time() - t_all, 2)
    OUT.mkdir(exist_ok=True)
    (OUT / ("toast_direct.json" if DIRECT else "toast_hook.json")).write_text(json.dumps(res, indent=1), encoding="utf-8")


main()
'''


# ----------------------------------------------------------------------- Claude Code in a sandbox
class ProbeClaude(Claude):
    """harness.Claude with a Windows-capable environment: the caller's environment minus anything that selects an
    account or provider, with every home-like variable pointed at the throwaway dir."""

    def __init__(self, out, base_url):
        super().__init__(out, base_url, env=None)
        home = str(self.tmp)
        env = {k: v for k, v in os.environ.items()
               if not (k.upper().startswith(("ANTHROPIC_", "AWS_", "GOOGLE_", "VERTEX", "CLOUD_ML_", "CLAUDE_")) or k == "CLAUDECODE")
               or k == "CLAUDE_CODE_GIT_BASH_PATH"}
        env.update(HOME=home, USERPROFILE=home, APPDATA=str(self.tmp / "AppData" / "Roaming"), LOCALAPPDATA=str(self.tmp / "AppData" / "Local"),
                   CLAUDE_CONFIG_DIR=str(self.config_dir), TEMP=home, TMP=home, TMPDIR=home, TERM="dumb", ANTHROPIC_MODEL=harness.MODEL,
                   ANTHROPIC_BASE_URL=base_url, CLAUDE_CODE_OAUTH_TOKEN=OAUTH, CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC="1",
                   DISABLE_AUTOUPDATER="1", DISABLE_TELEMETRY="1", **{PROBE_VAR: PROBE_VALUE})
        if IS_WIN:
            drive, rest = os.path.splitdrive(home)
            env.update(HOMEDRIVE=drive, HOMEPATH=rest)
        for sub in ("AppData/Roaming", "AppData/Local"):
            (self.tmp / sub).mkdir(parents=True, exist_ok=True)
        self.env = env

    def start(self, hook_events=False):
        cmd = [harness.CLAUDE, "-p", "--input-format", "stream-json", "--output-format", "stream-json", "--verbose"]
        if hook_events and CLAUDE_HAS_HOOK_EVENTS:
            cmd.append("--include-hook-events")
        self.proc = subprocess.Popen(cmd, cwd=self.tmp / "cwd", env=self.env, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                     stderr=open(self.out / "claude.stderr.txt", "a"), text=True, encoding="utf-8", errors="replace")
        threading.Thread(target=lambda: [self.lines.put(line) for line in self.proc.stdout] and self.lines.put(None), daemon=True).start()

    def stop(self):                                    # harness's stop() kills only the direct child; on Windows that can be a shim
        super().stop()
        if IS_WIN and self.proc and self.proc.poll() is None:
            subprocess.run(["taskkill", "/F", "/T", "/PID", str(self.proc.pid)], capture_output=True)


def run_capture(cmd, timeout=30):
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, encoding="utf-8", errors="replace")
        return (p.stdout or p.stderr).strip()
    except (OSError, subprocess.TimeoutExpired) as e:
        return f"error: {type(e).__name__}"


def new_session(out, name):
    """A mock gateway and a ProbeClaude whose sandbox dirs are under out/<name>."""
    sub = out / name
    sub.mkdir(parents=True, exist_ok=True)
    tempfile.tempdir = str(sub)                        # harness.Claude makes its dirs with mkdtemp: keep them under out
    gw = Gateway(sub)
    return sub, gw, ProbeClaude(sub, gw.url)


def tool_dir(out):
    """Where the hook scripts live: a directory with a space in its name, so every quoted form is also a quoting test."""
    d = out / "probe files"
    d.mkdir(parents=True, exist_ok=True)
    for name, text in (("hook_dump.py", HOOK_DUMP), ("hook_toast.py", HOOK_TOAST)):
        (d / name).write_text(text, encoding="utf-8")
    if IS_WIN:
        wrap = d / "pywrap.cmd"
        wrap.write_text(f'@"{sys.executable}" %*\r\n', encoding="utf-8")
    else:
        wrap = d / "pywrap.sh"
        wrap.write_text(f'#!/bin/sh\nexec "{sys.executable}" "$@"\n')
        wrap.chmod(0o755)
    return d, wrap


# ----------------------------------------------------------------------- basics
def phase_basics(out):
    global CLAUDE_HAS_HOOK_EVENTS
    observe("probe_platform", sys.platform)
    observe("os", one_line(platform.platform()))
    if IS_WIN:
        v = sys.getwindowsversion()
        observe("windows_build", f"{v.major}.{v.minor}.{v.build}")
        observe("windows_ver", one_line(run_capture(["cmd", "/c", "ver"])))
    observe("python_version", platform.python_version())
    observe("python_executable", sys.executable)
    observe("python_executable_has_space", "yes" if " " in sys.executable else "no")
    observe("probe_parents", ",".join(helpers.ancestors()))
    observe("claude_bin", shutil.which(harness.CLAUDE) or harness.CLAUDE)
    observe("claude_version", one_line(run_capture([harness.CLAUDE, "--version"])))
    CLAUDE_HAS_HOOK_EVENTS = "--include-hook-events" in run_capture([harness.CLAUDE, "--help"], 60)
    observe("claude_has_include_hook_events", "yes" if CLAUDE_HAS_HOOK_EVENTS else "no")
    if IS_WIN:
        roots = [os.environ.get(k) for k in ("ProgramFiles", "ProgramFiles(x86)", "LOCALAPPDATA")]
        gitbash = [str(Path(p) / "Git" / "bin" / "bash.exe") for p in roots if p and (Path(p) / "Git" / "bin" / "bash.exe").exists()]
        observe("git_for_windows_bash_exe", ";".join(gitbash) or "none")
        observe("git_on_path", shutil.which("git") or "none")
        observe("bash_on_path", shutil.which("bash") or "none")
        observe("claude_code_git_bash_path_env", "set" if os.environ.get("CLAUDE_CODE_GIT_BASH_PATH") else "unset")
        observe("powershell_5_1", one_line(run_capture(["powershell.exe", "-NoProfile", "-NonInteractive", "-Command",
                                                       "$PSVersionTable.PSVersion.ToString() + ' ' + $ExecutionContext.SessionState.LanguageMode"])))
        observe("pwsh_on_path", shutil.which("pwsh") or "none")
        observe("py_launcher", shutil.which("py") or "none")
        observe("python_exe_on_path", shutil.which("python.exe") or "none")
        observe("python3_on_path", shutil.which("python3") or "none")
    else:
        for k in ("git_for_windows_bash_exe", "git_on_path", "powershell_5_1", "py_launcher"):
            observe(k, "skipped (not windows)")


# ----------------------------------------------------------------------- hooks (S7.1)
def hook_cases(py, script, wrapper):
    """label -> (command, expected tail args or None, windows only[, extra hook fields]). The tail is what follows
    `case=<label>`. Extra fields: `args` (exec form, no shell) or `shell`."""
    import shlex
    s, fwd, pyf = str(script), Path(script).as_posix(), Path(py).as_posix()
    plain = ["a b", "back\\slash"]
    v = PROBE_VAR
    return {
        "dq": (f'"{py}" "{s}" case=dq "a b" back\\slash', plain, False),
        "sq": (f"{shlex.quote(py)} {shlex.quote(s)} case=sq 'a b' 'back\\slash'", plain, False),      # what the client's install writes today
        "fwd": (f'"{pyf}" "{fwd}" case=fwd "a b" back\\slash', plain, False),
        "bare_python": (f'python "{s}" case=bare_python "a b" back\\slash', plain, False),
        "python_exe": (f'python.exe "{s}" case=python_exe "a b" back\\slash', plain, True),
        "py3": (f'py -3 "{s}" case=py3 "a b" back\\slash', plain, True),
        "python3": (f'python3 "{s}" case=python3 "a b" back\\slash', plain, False),
        "pct": (f'"{py}" "{s}" case=pct %{v}% "%{v}%"', [PROBE_VALUE, PROBE_VALUE], False),
        "dollar": (f'"{py}" "{s}" case=dollar ${v} "${v}" ${{{v}}}', [PROBE_VALUE] * 3, False),
        "psenv": (f'"{py}" "{s}" case=psenv $env:{v}', [PROBE_VALUE], True),
        "psamp": (f'& "{py}" "{s}" case=psamp "a b" back\\slash', plain, True),
        "envprefix": (f'{v}=inline "{py}" "{s}" case=envprefix', [], False),
        "wrapper": (f'"{wrapper}" "{s}" case=wrapper "a b" back\\slash', plain, False),
        "cmd_c": (f'cmd /d /c ""{py}" "{s}" case=cmd_c "a b" back\\slash"', plain, True),
        "powershell_c": (f"powershell -NoProfile -Command \"& '{py}' '{s}' case=powershell_c 'a b' 'back\\slash'\"", plain, True),
        # Exec form: no shell on any platform, each element passed verbatim (hooks docs).
        "exec": (py, plain + [f"${v}", f"%{v}%"], False, {"args": [s, "case=exec", *plain, f"${v}", f"%{v}%"]}),
        "exec_py3": ("py", plain, True, {"args": ["-3", s, "case=exec_py3", *plain]}),
        "shell_ps": (f"& '{py}' '{s}' case=shell_ps 'a b' 'back\\slash'", plain, True, {"shell": "powershell"}),
    }


def shell_guess(ancestors):
    for a in ancestors or []:
        n = a.split("(")[0].lower()
        if n == "cmd.exe":
            return "cmd"
        if n in ("powershell.exe", "pwsh.exe", "pwsh", "powershell"):
            return "powershell"
        if n in ("bash.exe", "sh.exe", "bash", "sh", "zsh", "dash"):
            return "bash-like:" + n
    return "unknown"


def phase_hooks(out):
    tools, wrapper = tool_dir(out)
    dumps = tools / "dumps"
    shutil.rmtree(dumps, ignore_errors=True)
    sub, gw, claude = new_session(out, "hooks")
    allcases = hook_cases(sys.executable, tools / "hook_dump.py", wrapper)
    cases = {k: c for k, c in allcases.items() if IS_WIN or not c[2]}
    for k in allcases.keys() - cases.keys():
        observe(f"hook_{k}_ran", "skipped (windows only)")
    claude.write_settings({"hooks": {"UserPromptSubmit": [{"hooks": [
        {"type": "command", "command": c[0], "timeout": HOOK_TIMEOUT, **(c[3] if len(c) > 3 else {})}
        for c in cases.values()]}]}})
    (sub / "hook_commands.txt").write_text(
        "".join(f"{k}\t{c[0]}{chr(9) + json.dumps(c[3]) if len(c) > 3 else ''}\n" for k, c in cases.items()), encoding="utf-8")
    try:
        claude.start(hook_events=True)
        observe("hooks_turn", harness.classify(claude.turn("hook matrix", timeout=180)["text"]))
        wait_until(lambda: dumps.is_dir() and len(list(dumps.glob("*.json"))) >= len(cases), timeout=45)
    finally:
        claude.cleanup(), gw.close()
    stream = sub / "claude.stream.jsonl"
    events = [ln for ln in stream.read_text(encoding="utf-8", errors="replace").splitlines() if '"hook' in ln] if stream.exists() else []
    (sub / "hook_events.jsonl").write_text("".join(e[:4000] + "\n" for e in events), encoding="utf-8")
    observe("hook_events_in_stream", len(events))
    seen = {}
    for label, (cmd, want, *_) in cases.items():
        f = dumps / f"{label}.json"
        if not f.exists():
            observe(f"hook_{label}_ran", "no")
            continue
        d = seen[label] = json.loads(f.read_text(encoding="utf-8"))
        tail = [a for a in d["argv"][1:] if not a.startswith("case=")]
        observe(f"hook_{label}_ran", "yes")
        observe(f"hook_{label}_argv", json.dumps(tail, ensure_ascii=False))
        observe(f"hook_{label}_as_intended", "yes" if tail == want else "no")
        anc = d["ancestors"]
        observe(f"hook_{label}_parent", anc[0] if isinstance(anc, list) and anc else "unknown")
    ref = seen.get("dq") or seen.get("sq") or next(iter(seen.values()), None)
    if not ref:
        observe("hook_shell_guess", "no hook ran")
        return
    anc = ref["ancestors"]
    observe("hook_shell_guess", shell_guess(anc) if isinstance(anc, list) else "unknown")
    observe("hook_ancestors", ",".join(anc) if isinstance(anc, list) else anc)
    observe("hook_env", json.dumps({k: v for k, v in ref["env"].items() if v is not None}))
    observe("hook_env_present", json.dumps(ref["env_present"]))
    observe("hook_psmodulepath_has_windowspowershell", "yes" if ref["psmodulepath_has_windowspowershell"] else "no")
    observe("hook_executable", ref["executable"])
    observe("hook_cwd_is_project_dir", "yes" if Path(ref["cwd"]) == claude.tmp / "cwd" else "no")
    if IS_WIN and "dq" in seen:
        observe("hook_raw_cmdline_dq", one_line(seen["dq"].get("raw_cmdline", "n/a"), 600))
        observe("hook_parent_cmdline_dq", one_line(seen["dq"].get("parent_cmdline", "n/a"), 600))


# ----------------------------------------------------------------------- toast (S7.3)
def report_toast(where, res):
    observe(f"toast_{where}_total_seconds", res.get("total_seconds"))
    for name in ("ps_aumid", "own_aumid"):
        r = res.get(name, {})
        observe(f"toast_{where}_{name}_exit", r.get("exit", r.get("error", "missing")))
        observe(f"toast_{where}_{name}_seconds", r.get("seconds"))
        observe(f"toast_{where}_{name}_stdout", one_line(r.get("stdout", ""), 200))
        observe(f"toast_{where}_{name}_stderr", one_line(r.get("stderr", ""), 300))


def phase_toast(out, ask, hook_form):
    if not IS_WIN:
        observe("toast_status", "skipped (not windows)")
        return
    tools, wrapper = tool_dir(out)
    script = tools / "hook_toast.py"
    dumps = tools / "dumps"
    for f in dumps.glob("toast_*.json"):
        f.unlink()
    forms = hook_cases(sys.executable, script, wrapper)
    cmd = forms[hook_form][0].split(" case=")[0] if hook_form in forms else f'"{sys.executable}" "{script}"'
    cmd = cmd.replace(f"{PROBE_VAR}=inline ", "")
    sub, gw, claude = new_session(out, "toast")
    claude.write_settings({"hooks": {"UserPromptSubmit": [{"hooks": [{"type": "command", "command": cmd, "timeout": client_mod.HOOK_TIMEOUT}]}]}})
    observe("toast_hook_command_form", hook_form)
    print("ACTION: toasts titled 'Claude Code (winprobe)' are about to appear; note whether each was SEEN.", flush=True)
    try:
        claude.start(hook_events=True)
        observe("toast_turn", harness.classify(claude.turn("toast", timeout=120)["text"]))
        wait_until(lambda: (dumps / "toast_hook.json").exists(), timeout=45)
    finally:
        claude.cleanup(), gw.close()
    f = dumps / "toast_hook.json"
    observe("toast_hook_file", "yes" if f.exists() else "no")
    if f.exists():
        report_toast("hook", json.loads(f.read_text(encoding="utf-8")))
    # control: the same script run from this console, outside Claude Code
    p = subprocess.run([sys.executable, str(script), "direct"], capture_output=True, text=True, timeout=60)
    observe("toast_direct_exit", p.returncode)
    if (dumps / "toast_direct.json").exists():
        report_toast("direct", json.loads((dumps / "toast_direct.json").read_text(encoding="utf-8")))
    if ask and sys.stdin.isatty():
        for where in ("hook", "direct"):
            for name in ("ps_aumid", "own_aumid"):
                observe(f"toast_{where}_{name}_seen", input(f"Did the toast '{name}' ({where}) appear on screen? [y/n/?] ").strip() or "?")
    else:
        print("ACTION: toast_*_seen is a manual observation: note which toasts (ps_aumid / own_aumid, from the hook / direct) appeared "
              "and whether a console window flashed. Or re-run with --ask.", flush=True)


# ----------------------------------------------------------------------- lock (S7.2)
def replace_settings(path, text, retry_every=0.02, give_up=5.0):
    """The client's write_private, retried on PermissionError. Returns (fails, wait_seconds, error codes, gave_up)."""
    t0, fails, codes = time.perf_counter(), 0, []
    while True:
        try:
            client_mod.write_private(path, text)
            return fails, time.perf_counter() - t0, codes, False
        except PermissionError as e:
            fails += 1
            codes.append(getattr(e, "winerror", None) or e.errno)
            if time.perf_counter() - t0 > give_up:
                return fails, time.perf_counter() - t0, codes, True
            time.sleep(retry_every)


def settings_text(jwt):
    return json.dumps({"env": {"ANTHROPIC_CUSTOM_HEADERS": f"{PK}: {jwt}"}}, indent=2)


def lock_control(out):
    """Proves the detector works: replacing a file this process holds open without delete sharing (Python's open() on
    Windows) must raise PermissionError there; on POSIX it succeeds."""
    d = out / "lock-control"
    d.mkdir(parents=True, exist_ok=True)
    f = d / "settings.json"
    f.write_text("{}")
    with open(f, "r"):
        fails, _, codes, gave_up = replace_settings(f, settings_text(fresh_jwt()), give_up=0.5)
    observe("lock_control_held_open_permission_errors", fails)
    observe("lock_control_held_open_error_codes", ",".join(map(str, sorted(set(codes)))) or "none")
    observe("lock_control_held_open_gave_up", "yes" if gave_up else "no")


def hammer(gw, claude, rounds, spacing, pickup_rounds, interactive=False):
    """Replace settings.json `rounds` times while turns run (or the person types), then `pickup_rounds` replacements whose
    new JWT must show up at the gateway."""
    f = claude.settings_file
    f.write_text(settings_text(fresh_jwt()))
    stop, stats = threading.Event(), {"turns": 0, "turn_errors": 0}

    def pump():
        while not stop.is_set():
            t = claude.turn(f"lock turn {stats['turns']}", timeout=60)
            stats["turns"] += 1
            stats["turn_errors"] += bool(t["is_error"])
            time.sleep(0.1)

    th = None
    if not interactive:
        claude.start()
        th = threading.Thread(target=pump, daemon=True)
        th.start()
    mark = gw.mark()
    wait_until(lambda: gw.mark() > mark, timeout=300 if interactive else 60, step=0.5)
    observe("lock_first_request_seen", "yes" if gw.mark() > mark else "no")
    mark = gw.mark()
    waits, fails, codes, gave, bad_rounds = [], 0, [], 0, 0
    for _ in range(rounds):
        fa, wa, er, gu = replace_settings(f, settings_text(fresh_jwt()))
        waits.append(wa * 1000)
        fails, gave, bad_rounds = fails + fa, gave + gu, bad_rounds + (fa > 0)
        codes += er
        time.sleep(spacing)
    observe("lock_rounds", rounds)
    observe("lock_requests_during", gw.mark() - mark)
    observe("lock_permission_errors", fails)
    observe("lock_rounds_with_error", bad_rounds)
    observe("lock_gave_up", gave)
    observe("lock_max_wait_ms", round(max(waits), 1))
    observe("lock_median_wait_ms", round(sorted(waits)[len(waits) // 2], 1))
    observe("lock_error_codes", ",".join(map(str, sorted(set(codes)))) or "none")
    try:
        json.loads(f.read_text())
        observe("lock_settings_valid", "yes")
    except ValueError:
        observe("lock_settings_valid", "no")
    picked = []
    for i in range(pickup_rounds):
        jwt = fresh_jwt()
        want = mock_gateway.fingerprint(jwt)
        mark, t0 = gw.mark(), time.time()
        replace_settings(f, settings_text(jwt))
        if interactive:
            print(f"ACTION: send a prompt now ({i + 1}/{pickup_rounds}); waiting up to 90 s for a request with the new header.", flush=True)
        ok = wait_until(lambda: any(r["headers"].get(PK) == want for r in gw.messages(mark)), timeout=90 if interactive else 20, step=0.25)
        picked.append(round(time.time() - t0, 1) if ok else None)
        observe(f"lock_pickup_{i + 1}_seconds", picked[-1] if ok else "never")
        time.sleep(2)
    observe("lock_pickup_ok", "yes" if picked and all(p is not None for p in picked) else "no")
    stop.set()
    if th:
        th.join(timeout=70)
        observe("lock_turns_during", stats["turns"])
        observe("lock_turn_errors", stats["turn_errors"])


def write_launchers(sub, claude):
    """Scripts that start the real TUI in the sandbox, with the same environment as the headless sessions."""
    keys = [k for k in ("HOME", "USERPROFILE", "APPDATA", "LOCALAPPDATA", "TEMP", "TMP", "CLAUDE_CONFIG_DIR", "ANTHROPIC_BASE_URL",
                        "ANTHROPIC_MODEL", "CLAUDE_CODE_OAUTH_TOKEN", "DISABLE_AUTOUPDATER") if k in claude.env]
    cwd = claude.tmp / "cwd"
    if IS_WIN:
        (sub / "run-tui.cmd").write_text("@echo off\r\n" + "".join(f'set "{k}={claude.env[k]}"\r\n' for k in keys) + f'cd /d "{cwd}"\r\n"{harness.CLAUDE}"\r\n')
        (sub / "run-tui.ps1").write_text("".join(f"$env:{k} = '{claude.env[k]}'\r\n" for k in keys) + f"Set-Location '{cwd}'\r\n& '{harness.CLAUDE}'\r\n")
        how = f"{sub / 'run-tui.cmd'}  (cmd)  or  powershell -File {sub / 'run-tui.ps1'}"
    else:
        sh = sub / "run-tui.sh"
        sh.write_text("#!/bin/sh\n" + "".join(f"export {k}='{claude.env[k]}'\n" for k in keys) + f"cd '{cwd}'\nexec '{harness.CLAUDE}'\n")
        sh.chmod(0o755)
        how = str(sh)
    print(f"ACTION: in a second terminal run  {how}  and keep sending prompts (any text) until this probe says probe_done. "
          f"The TUI may ask first-run questions; answer them.", flush=True)


def phase_lock(out, rounds, interactive=False):
    lock_control(out)
    sub, gw, claude = new_session(out, "interactive" if interactive else "lock")
    try:
        if interactive:
            write_launchers(sub, claude)
        hammer(gw, claude, rounds, 0.25 if interactive else 0.1, 3, interactive)
    finally:
        claude.cleanup(), gw.close()


# ----------------------------------------------------------------------- main
def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--out", type=Path, required=True)
    ap.add_argument("--only", default="basics,hooks,lock,toast", help="comma list of: basics hooks lock toast interactive")
    ap.add_argument("--ask", action="store_true", help="ask on the console whether each toast was seen")
    ap.add_argument("--lock-rounds", type=int, default=60, help="replacements in the hammer phase (default 60, 0.1 s apart; interactive: at least 200, 0.25 s apart)")
    ap.add_argument("--hook-form", default="dq", help="hook command form the toast hook uses: a label from the hooks matrix (default dq)")
    a = ap.parse_args()
    a.out = a.out.resolve()
    a.out.mkdir(parents=True, exist_ok=True)
    phases = {p.strip() for p in a.only.split(",") if p.strip()}
    observe("probe_version", 1)
    phase_basics(a.out)                                # always: it also detects --include-hook-events
    if "hooks" in phases:
        phase_hooks(a.out)
    if "lock" in phases:
        phase_lock(a.out, a.lock_rounds)
    if "interactive" in phases:
        phase_lock(a.out, max(a.lock_rounds, 200), interactive=True)
    if "toast" in phases:
        phase_toast(a.out, a.ask, a.hook_form)
    observe("probe_done", "yes")


if __name__ == "__main__":
    main()
