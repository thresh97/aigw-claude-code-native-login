#!/usr/bin/env python3
"""Render and package aigw-claude-auth for a fleet (Python 3.8+, standard library only).

One input file (packaging/fleet.example.json) holds the gateway URL, the mode and the IdP profile. This script renders the
artifacts from it and builds the per-OS packages. It imports the client (../client/aigw_claude_auth.py) for the hook
entries (`hook_entry`), the proxy address (`proxy_base_url`), config validation (`load_config`) and the Task Scheduler
XML (`task_xml`), so nothing about the client's behavior is duplicated here.

  build.py render --fleet F --out DIR [--os macos|linux|windows|all]   write the rendered files (no packages)
  build.py macos   --fleet F --out DIR [--sign IDENTITY]               DIR/aigw-claude-auth-<ver>.pkg (needs pkgbuild, productbuild)
  build.py linux   --fleet F --out DIR [--rpm]                         .deb (and .rpm) built inside Docker
  build.py windows --fleet F --out DIR                                 DIR/windows/: installer scripts + payload

Real packages refuse a fleet file that still holds <placeholders> (use --allow-placeholders for a dry build).
"""
import argparse
import importlib.util
import json
import os
import plistlib
import re
import shlex
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path, PureWindowsPath

HERE = Path(__file__).resolve().parent
CLIENT_PATH = HERE.parent / "client" / "aigw_claude_auth.py"
LAUNCHER_PATH = HERE / "aigw_launch.py"
SERVICE_IDENTIFIER = "org.aigw.claude-auth"      # macOS pkg identifier

TOP_KEYS = {"name", "gateway_url", "mode", "proxy_listen", "idp", "options", "python", "package_revision"}
OPTION_KEYS = {"pin_allowed_providers", "allow_managed_hooks_only", "notify"}
# Fleet-wide profile keys that also go into managed `env` as AIGW_<KEY> (finding 15). The client reads
# AIGW_LOGIN_METHOD and AIGW_HOOK_LOGIN itself; `doctor` compares the others with the helper config (all strings, so
# the comparison is exact).
AIGW_ENV_KEYS = ("issuer", "client_id", "scope", "redirect_port", "login_method", "hook_login", "mode")

LAYOUT = {
    "macos": {
        "install_dir": "/usr/local/libexec/aigw-claude-auth",
        "managed_dir": "/Library/Application Support/ClaudeCode/managed-settings.d",
        "bgstart_dir": "/Library/LaunchAgents",
    },
    "linux": {
        "install_dir": "/usr/lib/aigw-claude-auth",
        "managed_dir": "/etc/claude-code/managed-settings.d",
        "bgstart_dir": "/usr/lib/systemd/user",
    },
    "windows": {
        "install_dir": r"C:\Program Files\aigw-claude-auth",
        "managed_dir": r"C:\Program Files\ClaudeCode\managed-settings.d",
        "bgstart_dir": r"C:\Program Files\aigw-claude-auth",
    },
}


class BuildError(Exception):
    pass


_CLIENT = []


def load_client():
    if _CLIENT:
        return _CLIENT[0]
    spec = importlib.util.spec_from_file_location("aigw_claude_auth_client", CLIENT_PATH)
    mod = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = mod
    spec.loader.exec_module(mod)
    _CLIENT.append(mod)
    return mod


# --------------------------------------------------------------------------------------------- fleet file

def load_fleet(path):
    fleet = json.loads(Path(path).read_text(encoding="utf-8"))
    if not isinstance(fleet, dict):
        raise BuildError("the fleet file must be a JSON object")
    unknown = set(fleet) - TOP_KEYS
    if unknown:
        raise BuildError("unknown keys in the fleet file: " + ", ".join(sorted(unknown)))
    unknown = set(fleet.get("options", {})) - OPTION_KEYS
    if unknown:
        raise BuildError("unknown options: " + ", ".join(sorted(unknown)))
    fleet.setdefault("name", "aigw-claude-auth")
    fleet.setdefault("mode", "file")
    fleet.setdefault("proxy_listen", "127.0.0.1:18787")
    fleet.setdefault("idp", {})
    fleet.setdefault("options", {})
    fleet.setdefault("python", {})
    fleet.setdefault("package_revision", 1)
    if not re.fullmatch(r"[a-z0-9][a-z0-9.-]*", fleet["name"]) or "aigw" not in fleet["name"].replace("_", "-"):
        raise BuildError("name must be lowercase letters, digits, dots and dashes, and contain 'aigw' (the client finds its hooks by that)")
    if not fleet.get("gateway_url"):
        raise BuildError("gateway_url is required (file mode: ANTHROPIC_BASE_URL; proxy mode: where the proxy forwards)")
    return fleet


def find_placeholders(fleet):
    found = []

    def walk(v, where):
        if isinstance(v, dict):
            for k, x in v.items():
                walk(x, f"{where}.{k}" if where else k)
        elif isinstance(v, str) and re.search(r"<[^<>]+>", v):
            found.append(where)
    walk(fleet, "")
    return found


def client_config(fleet, client):
    """The config.json every user gets (read from the install dir by the launcher and the hooks)."""
    cfg = dict(fleet["idp"])
    cfg.update(mode=fleet["mode"], proxy_listen=fleet["proxy_listen"])
    if fleet["mode"] == "proxy":        # file mode keeps the gateway URL in the managed ANTHROPIC_BASE_URL only (one place, no mismatch)
        cfg["gateway_url"] = fleet["gateway_url"]
    if "notify" in fleet["options"]:
        cfg["notify"] = fleet["options"]["notify"]
    with tempfile.TemporaryDirectory() as d:        # the client's own validation: unknown keys, bad enums, non-loopback proxy
        p = Path(d) / "config.json"
        p.write_text(json.dumps(cfg))
        try:
            client.load_config(p)
        except (client.AuthError, ValueError) as e:
            raise BuildError(f"the client would refuse this config: {e}")
    return cfg


# --------------------------------------------------------------------------------------------- rendering

def paths_for(osname, fleet):
    lay = LAYOUT[osname]
    name = fleet["name"]
    if osname == "windows":
        w = PureWindowsPath(lay["install_dir"])
        return {"install_dir": lay["install_dir"], "client": str(w / "aigw_claude_auth.py"), "launcher": str(w / "aigw_launch.py"),
                "config": str(w / "config.json"), "managed": str(PureWindowsPath(lay["managed_dir"]) / f"50-{name}.json"),
                "bgstart": str(w / "task.xml")}
    d = lay["install_dir"]
    bg = f"{name}.fleet.plist" if osname == "macos" else f"{name}.service"
    return {"install_dir": d, "client": f"{d}/aigw_claude_auth.py", "launcher": f"{d}/aigw_launch.py", "config": f"{d}/config.json",
            "managed": f"{lay['managed_dir']}/50-{name}.json", "bgstart": f"{lay['bgstart_dir']}/{bg}"}


def hook_command(osname, paths, fleet):
    """What the managed hooks run: the client with the fleet's config. POSIX: a shell string; Windows: exec-form argv."""
    py = fleet["python"].get(osname) or "/usr/bin/python3"
    if osname == "windows":
        return [py, paths["client"], "--config", paths["config"]]
    return f"{shlex.quote(py)} {shlex.quote(paths['client'])} --config {shlex.quote(paths['config'])}"


def managed_settings(osname, fleet, client, cfg, paths):
    proxy = fleet["mode"] == "proxy"
    try:
        base_url = client.proxy_base_url(cfg) if proxy else fleet["gateway_url"]
    except client.AuthError as e:
        raise BuildError(str(e))
    hook = hook_command(osname, paths, fleet)
    env = {"ANTHROPIC_BASE_URL": base_url}
    for key in AIGW_ENV_KEYS:
        if key in cfg:
            env["AIGW_" + key.upper()] = str(cfg[key])
    out = {"env": env,
           "hooks": {"UserPromptSubmit": [client.hook_entry(hook, "precheck")], "StopFailure": [client.hook_entry(hook, "stop-failure")]}}
    if fleet["options"].get("pin_allowed_providers", True):
        out["allowedProviders"] = ["customEndpoint"]
    if fleet["options"].get("allow_managed_hooks_only"):
        out["allowManagedHooksOnly"] = True
    return out      # never ANTHROPIC_CUSTOM_HEADERS: a managed value replaces the user's, JWT and proxy secret included (finding 11)


def launchd_plist(fleet, paths):
    py = fleet["python"].get("macos") or "/usr/bin/python3"
    return plistlib.dumps({
        "Label": f"{fleet['name']}.fleet",
        "ProgramArguments": [py, paths["launcher"], "daemon"],
        "EnvironmentVariables": {"PATH": "/usr/bin:/bin:/usr/sbin:/sbin"},
        "RunAtLoad": True,
        "KeepAlive": {"SuccessfulExit": False},
        "ThrottleInterval": 10,
        "ProcessType": "Background",
        "StandardErrorPath": "/dev/null",       # the launcher opens ~/Library/Logs/aigw-claude-auth.log itself
        "StandardOutPath": "/dev/null",
    })


def systemd_unit(fleet, paths):
    py = fleet["python"].get("linux") or "/usr/bin/python3"
    return f"""# Generated by packaging/build.py. Enabled for every user with `systemctl --global enable {fleet['name']}.service`.
[Unit]
Description=Gateway JWT refresher for Claude Code (aigw-claude-auth)
After=network-online.target

[Service]
ExecStart={py} {paths['launcher']} daemon
Restart=on-failure
RestartSec=10

[Install]
WantedBy=default.target
""".encode()


def windows_task_xml(fleet, client, paths):
    """The client's own task definition, changed from one named user to anyone in the local Users group."""
    py = fleet["python"].get("windows") or r"C:\Program Files\Python312\python.exe"
    xml = client.task_xml("__USER__", py, paths["launcher"])
    trigger = "<LogonTrigger><Enabled>true</Enabled><UserId>__USER__</UserId></LogonTrigger>"
    principal = "<UserId>__USER__</UserId><LogonType>InteractiveToken</LogonType>"
    if trigger not in xml or principal not in xml:
        raise BuildError("the client's task_xml changed shape; update windows_task_xml")
    xml = xml.replace(trigger, "<LogonTrigger><Enabled>true</Enabled></LogonTrigger>")
    xml = xml.replace(principal, "<GroupId>S-1-5-32-545</GroupId>")
    if py.lower().endswith("python.exe") and "pythonw.exe" not in xml:
        xml = xml.replace(py, py[:-len("python.exe")] + "pythonw.exe", 1)        # no console window
    return xml


def render(fleet, osname):
    """(files, paths): files maps a role (client, launcher, config, managed, bgstart) to bytes; paths maps it to its install path."""
    client = load_client()
    cfg = client_config(fleet, client)
    paths = paths_for(osname, fleet)
    files = {
        "client": CLIENT_PATH.read_bytes(),
        "launcher": LAUNCHER_PATH.read_bytes(),
        "config": (json.dumps(cfg, indent=2) + "\n").encode(),
        "managed": (json.dumps(managed_settings(osname, fleet, client, cfg, paths), indent=2) + "\n").encode(),
    }
    if osname == "macos":
        files["bgstart"] = launchd_plist(fleet, paths)
    elif osname == "linux":
        files["bgstart"] = systemd_unit(fleet, paths)
    else:
        files["bgstart"] = windows_task_xml(fleet, client, paths).encode("utf-16")
    return files, paths


def package_version():
    return load_client().VERSION


def write_stage(root, files, paths, modes=None):
    """Lay the files out under `root` at their install paths (POSIX targets). Returns the list of relative file paths."""
    out = []
    for role, data in files.items():
        dest = Path(str(root) + paths[role])
        dest.parent.mkdir(parents=True, exist_ok=True)
        dest.write_bytes(data)
        mode = 0o755 if role in ("client", "launcher") else 0o644
        dest.chmod(mode)
        out.append(paths[role])
    return out


def fill(template, **kw):
    for k, v in kw.items():
        template = template.replace(f"@{k.upper()}@", str(v))
    return template


def copy_script(src, dst, mode=0o755, **kw):
    Path(dst).parent.mkdir(parents=True, exist_ok=True)
    Path(dst).write_text(fill(Path(src).read_text(), **kw))
    os.chmod(dst, mode)


# --------------------------------------------------------------------------------------------- macOS

def build_macos(fleet, out, sign=None):
    files, paths = render(fleet, "macos")
    ver = package_version()
    label = f"{fleet['name']}.fleet"
    out = Path(out)
    work = out / "macos-work"
    shutil.rmtree(work, ignore_errors=True)
    stage, scripts = work / "root", work / "scripts"
    write_stage(stage, files, paths)
    kw = dict(label=label, install_dir=paths["install_dir"], managed=paths["managed"], plist=paths["bgstart"],
              identifier=SERVICE_IDENTIFIER, name=fleet["name"], python=fleet["python"].get("macos") or "/usr/bin/python3")
    copy_script(HERE / "macos" / "postinstall", scripts / "postinstall", **kw)
    copy_script(HERE / "macos" / "uninstall.sh", Path(str(stage) + paths["install_dir"]) / "uninstall.sh", **kw)
    component = work / "component.pkg"
    run(["pkgbuild", "--root", str(stage), "--scripts", str(scripts), "--identifier", SERVICE_IDENTIFIER, "--version", ver,
         "--install-location", "/", "--ownership", "recommended", str(component)])
    final = out / f"{fleet['name']}-{ver}.pkg"
    cmd = ["productbuild", "--package", str(component), "--identifier", SERVICE_IDENTIFIER, "--version", ver]
    if sign:
        cmd += ["--sign", sign]         # a "Developer ID Installer" identity; notarize the result with `xcrun notarytool`
    run(cmd + [str(final)])
    return final


# --------------------------------------------------------------------------------------------- Linux

DEB_CONTROL = """Package: {name}
Version: {ver}-{rev}
Architecture: all
Maintainer: {maint}
Depends: python3 (>= 3.8)
Section: utils
Priority: optional
Description: Gateway JWT for Claude Code (aigw-claude-auth)
 Keeps a gateway JWT fresh for Claude Code. Installs the client, Claude Code managed
 settings (drop-in) and a systemd user unit enabled for all users.
"""

RPM_SPEC = """Name: {name}
Version: {ver}
Release: {rev}
Summary: Gateway JWT for Claude Code (aigw-claude-auth)
License: See repository
BuildArch: noarch
Requires: python3 >= 3.8
AutoReqProv: no

%description
Keeps a gateway JWT fresh for Claude Code. Installs the client, Claude Code managed settings (drop-in) and a systemd user
unit enabled for all users.

%install
cp -a {stage}/. %{{buildroot}}/

%files
{files}

%post
@POSTINST@

%preun
if [ "$1" = "0" ]; then
@PRERM@
fi
"""


def linux_scripts(fleet, paths):
    unit = Path(paths["bgstart"]).name
    kw = dict(unit=unit, install_dir=paths["install_dir"], managed=paths["managed"], name=fleet["name"])
    return {n: fill((HERE / "linux" / n).read_text(), **kw) for n in ("postinst", "prerm", "postrm")}


def build_linux(fleet, out, rpm=False):
    files, paths = render(fleet, "linux")
    ver, rev, name = package_version(), fleet["package_revision"], fleet["name"]
    out = Path(out)
    work = out / "linux-work"
    shutil.rmtree(work, ignore_errors=True)
    stage = work / "deb"
    rel = write_stage(stage, files, paths)
    scripts = linux_scripts(fleet, paths)
    deb = stage / "DEBIAN"
    deb.mkdir()
    (deb / "control").write_text(DEB_CONTROL.format(name=name, ver=ver, rev=rev, maint=fleet.get("maintainer", "IT <it@example.invalid>")))
    for n, text in scripts.items():
        (deb / n).write_text(text)
        (deb / n).chmod(0o755)
    debfile = f"{name}_{ver}-{rev}_all.deb"
    docker(["debian:12", "sh", "-c", f"dpkg-deb --root-owner-group --build /stage /out/{debfile}"],
           mounts={str(stage): "/stage", str(out): "/out"})
    result = [out / debfile]
    if rpm:
        rstage = work / "rpm"
        write_stage(rstage, files, paths)
        spec = RPM_SPEC.format(name=name, ver=ver, rev=rev, stage="/stage", files=f"%dir {paths['install_dir']}\n" + "\n".join(rel))
        spec = spec.replace("@POSTINST@", strip_shebang(scripts["postinst"])).replace("@PRERM@", strip_shebang(scripts["prerm"]))
        (work / "pkg.spec").write_text(spec)
        rpmfile = f"{name}-{ver}-{rev}.noarch.rpm"
        docker(["rockylinux:9", "sh", "-c",
                "dnf -q -y install rpm-build >/dev/null && rpmbuild -bb --define '_rpmdir /out' --define '_build_id_links none' "
                f"/work/pkg.spec >/dev/null && cp /out/noarch/{rpmfile} /out/{rpmfile}"],
               mounts={str(rstage): "/stage", str(work): "/work", str(out): "/out"})
        result.append(out / rpmfile)
    return result


def strip_shebang(text):
    return "\n".join(l for l in text.splitlines() if not l.startswith("#!"))


def docker(args, mounts):
    cmd = ["docker", "run", "--rm"]
    for host, ctr in mounts.items():
        cmd += ["-v", f"{host}:{ctr}"]
    run(cmd + args)


# --------------------------------------------------------------------------------------------- Windows

def build_windows(fleet, out):
    files, paths = render(fleet, "windows")
    dest = Path(out) / "windows"
    shutil.rmtree(dest, ignore_errors=True)
    payload = dest / "payload"
    payload.mkdir(parents=True)
    for role, fn in (("client", "aigw_claude_auth.py"), ("launcher", "aigw_launch.py"), ("config", "config.json"),
                     ("managed", f"50-{fleet['name']}.json"), ("bgstart", "task.xml")):
        (payload / fn).write_bytes(files[role])
    for ps in ("Install-AigwClaudeAuth.ps1", "Uninstall-AigwClaudeAuth.ps1"):
        shutil.copy(HERE / "windows" / ps, dest / ps)
    (dest / "payload" / "fleet.txt").write_text(f"name={fleet['name']}\nversion={package_version()}\npython={fleet['python'].get('windows', '')}\n")
    return dest


# --------------------------------------------------------------------------------------------- CLI

def run(cmd):
    print("+ " + " ".join(shlex.quote(c) for c in cmd), file=sys.stderr)
    subprocess.run(cmd, check=True)


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    sub = ap.add_subparsers(dest="cmd", required=True)
    for name in ("render", "macos", "linux", "windows"):
        p = sub.add_parser(name)
        p.add_argument("--fleet", required=True, type=Path)
        p.add_argument("--out", required=True, type=Path)
        p.add_argument("--allow-placeholders", action="store_true", help="build even though the fleet file still holds <placeholders>")
        if name == "render":
            p.add_argument("--os", choices=["macos", "linux", "windows", "all"], default="all")
        if name == "macos":
            p.add_argument("--sign", metavar="IDENTITY", help="productbuild --sign: a 'Developer ID Installer: ...' identity")
        if name == "linux":
            p.add_argument("--rpm", action="store_true", help="also build an .rpm (rockylinux:9 in Docker)")
    a = ap.parse_args(argv)
    try:
        fleet = load_fleet(a.fleet)
        ph = find_placeholders(fleet)
        if ph and a.cmd != "render" and not a.allow_placeholders:
            raise BuildError("the fleet file still holds placeholders in: " + ", ".join(ph) + " (--allow-placeholders for a dry build)")
        a.out.mkdir(parents=True, exist_ok=True)
        if a.cmd == "render":
            for osname in (["macos", "linux", "windows"] if a.os == "all" else [a.os]):
                files, paths = render(fleet, osname)
                for role, data in files.items():
                    tgt = a.out / osname / role
                    tgt.parent.mkdir(parents=True, exist_ok=True)
                    tgt.write_bytes(data)
                    print(f"{osname}/{role} -> {paths[role]}")
        elif a.cmd == "macos":
            print(build_macos(fleet, a.out, a.sign))
        elif a.cmd == "linux":
            for p in build_linux(fleet, a.out, a.rpm):
                print(p)
        else:
            print(build_windows(fleet, a.out))
    except (BuildError, subprocess.CalledProcessError) as e:
        print(f"error: {e}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
