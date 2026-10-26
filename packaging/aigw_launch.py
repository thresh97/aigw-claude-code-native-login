#!/usr/bin/env python3
"""Per-user launcher for the fleet packages (standard library only; sits next to aigw_claude_auth.py and config.json).

  aigw_launch.py [daemon]   what the LaunchAgent, systemd user unit and Windows logon task run. Runs
                            `install --no-hooks` for the signed-in user (their JWT line, or in proxy mode the proxy
                            address and their own secret: idempotent), then the daemon, both with the fleet's
                            config.json. The managed settings already carry the hooks and the base URL.
  aigw_launch.py purge-user undo the per-user part for the user running it: forget the refresh token, remove our
                            header lines and the config/state directory. Run by the uninstallers on request.

The fleet config is read from the install directory, never copied per user, so a package upgrade changes it for everyone.
"""
import importlib.util
import os
import shutil
import sys
import time

HERE = os.environ.get("AIGW_FLEET_DIR") or os.path.dirname(os.path.realpath(__file__))


def load_client():
    spec = importlib.util.spec_from_file_location("aigw_claude_auth", os.path.join(HERE, "aigw_claude_auth.py"))
    mod = importlib.util.module_from_spec(spec)
    sys.modules["aigw_claude_auth"] = mod
    spec.loader.exec_module(mod)
    return mod


def log(msg):
    print(f"{time.strftime('%Y-%m-%d %H:%M:%S')} aigw_launch: {msg}", file=sys.stderr, flush=True)


def redirect_log_on_mac():
    """launchd cannot expand ~ in StandardErrorPath, so the launcher opens the per-user log itself."""
    if sys.platform != "darwin" or sys.stderr.isatty():
        return
    d = os.path.expanduser("~/Library/Logs")
    try:
        os.makedirs(d, exist_ok=True)
        fd = os.open(os.path.join(d, "aigw-claude-auth.log"), os.O_WRONLY | os.O_APPEND | os.O_CREAT, 0o600)
        os.dup2(fd, 1)
        os.dup2(fd, 2)
    except OSError:
        pass


def purge_user(client, base):
    cfg = client.load_config(client.Path(base[1]))
    client.main(base + ["logout"])
    settings = client.Settings(client.default_settings_path(), cfg["header"])
    if settings.path.exists():
        settings.apply(drop_lines=[cfg["header"], client.LOCAL_HEADER], drop_base_url=lambda u: client.is_proxy_url(cfg, u))
    shutil.rmtree(str(client.config_dir()), ignore_errors=True)
    log(f"removed our header lines from {settings.path} and the directory {client.config_dir()}")
    return 0


def main(argv):
    cmd = argv[0] if argv else "daemon"
    redirect_log_on_mac()
    client = load_client()
    base = ["--config", os.path.join(HERE, "config.json")]
    if cmd == "purge-user":
        return purge_user(client, base)
    try:
        rc = client.main(base + ["install", "--no-hooks"])
        log(f"first-run install --no-hooks exit {rc}")
    except Exception as e:      # the daemon must still start; its own loop reports a broken config
        log(f"first-run install --no-hooks failed: {e}")
    return client.main(base + ["daemon"])


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
