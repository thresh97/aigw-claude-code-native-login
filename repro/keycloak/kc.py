"""A local Keycloak for the `keycloak` scenario: start/stop it in Docker (or use one already running), create the
dummy test user over the admin REST API, and play the user's side of a device-code sign-in without a browser.

Standard library only. Nothing here prints or stores a token or password: the user's password and the admin password are
generated per run and live in memory (and in the container's environment, which is thrown away with it).

Environment:
  KEYCLOAK_URL             use a Keycloak that is already running (e.g. a CI service container), e.g. http://127.0.0.1:8080
  KEYCLOAK_ADMIN_USER      its bootstrap admin (default admin)
  KEYCLOAK_ADMIN_PASSWORD  its password (required with KEYCLOAK_URL)
  KEYCLOAK_PORT            host port for the container we start (default: a free one), bound to 127.0.0.1 only
"""
import html
import http.client
import json
import re
import secrets
import shutil
import socket
import subprocess
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

HERE = Path(__file__).resolve().parent
IMAGE = "quay.io/keycloak/keycloak:26.4.7"       # pinned; the realm file and the HTML scraping below are known to work with it
REALM = "aigw-test"
REALM_FILE = HERE / "realm-aigw-test.json"
USERNAME = "aigw-user"


def docker_available():
    """None if `docker` works, else why not."""
    if not shutil.which("docker"):
        return "docker not found"
    try:
        p = subprocess.run(["docker", "info"], capture_output=True, timeout=30)
    except (OSError, subprocess.TimeoutExpired):
        return "docker info failed"
    return None if p.returncode == 0 else "docker daemon not running"


def free_port():
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def call(method, url, data=None, headers=None, form=None, timeout=30):
    """(status, body bytes). JSON for data, urlencoded for form. Never raises on an HTTP error status."""
    h = dict(headers or {})
    body = None
    if form is not None:
        body = urllib.parse.urlencode(form).encode()
        h["Content-Type"] = "application/x-www-form-urlencoded"
    elif data is not None:
        body = json.dumps(data).encode()
        h["Content-Type"] = "application/json"
    req = urllib.request.Request(url, data=body, headers=h, method=method)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return r.status, r.read()
    except urllib.error.HTTPError as e:
        return e.code, e.read()


class Keycloak:
    def __init__(self, env):
        """env: os.environ (or a dict). Does not start anything yet."""
        self.container = None
        external = env.get("KEYCLOAK_URL")
        self.base = external.rstrip("/") if external else None
        self.admin_user = env.get("KEYCLOAK_ADMIN_USER") or "admin"
        self.admin_password = env.get("KEYCLOAK_ADMIN_PASSWORD") or ""
        self.port = int(env["KEYCLOAK_PORT"]) if env.get("KEYCLOAK_PORT") else None
        self.user_password = secrets.token_urlsafe(18)       # the test user's; throwaway
        self.user_id = None

    @property
    def issuer(self):
        return f"{self.base}/realms/{REALM}"

    # ---------------------------------------------------------------- lifecycle
    def start(self, wait=180):
        if self.base:
            if not self.admin_password:
                raise RuntimeError("KEYCLOAK_URL is set but KEYCLOAK_ADMIN_PASSWORD is not")
        else:
            why = docker_available()
            if why:
                raise RuntimeError(why)
            self.admin_password = secrets.token_urlsafe(18)
            self.port = self.port or free_port()
            self.base = f"http://127.0.0.1:{self.port}"
            self.container = f"aigw-kc-{secrets.token_hex(3)}"
            realm = HERE / "realm-aigw-test.json"
            p = subprocess.run(
                ["docker", "run", "-d", "--name", self.container, "-p", f"127.0.0.1:{self.port}:8080",
                 "-e", "KC_BOOTSTRAP_ADMIN_USERNAME=" + self.admin_user, "-e", "KC_BOOTSTRAP_ADMIN_PASSWORD=" + self.admin_password,
                 "-v", f"{realm}:/opt/keycloak/data/import/realm-aigw-test.json:ro",
                 IMAGE, "start-dev", "--import-realm"], capture_output=True, encoding="utf-8")
            if p.returncode != 0:
                self.container = None
                raise RuntimeError("docker run failed: " + (p.stderr or "").strip()[-300:])
        end = time.time() + wait
        url = f"{self.issuer}/.well-known/openid-configuration"
        while time.time() < end:
            try:
                if call("GET", url, timeout=5)[0] == 200:
                    break
            except (urllib.error.URLError, OSError):
                pass
            time.sleep(2)
        else:
            raise RuntimeError(f"Keycloak did not come up at {self.base} within {wait}s")
        self.create_user()

    def stop(self):
        if self.container:
            subprocess.run(["docker", "rm", "-f", "-v", self.container], capture_output=True)
            self.container = None

    def version(self):
        return IMAGE.rsplit(":", 1)[1]

    # ---------------------------------------------------------------- admin REST API
    def admin_token(self):
        s, b = call("POST", f"{self.base}/realms/master/protocol/openid-connect/token",
                    form={"grant_type": "password", "client_id": "admin-cli", "username": self.admin_user, "password": self.admin_password})
        if s != 200:
            raise RuntimeError(f"admin login failed (HTTP {s})")
        return json.loads(b)["access_token"]

    def admin(self, method, path, data=None):
        s, b = call(method, f"{self.base}/admin/realms/{REALM}{path}", data=data, headers={"Authorization": "Bearer " + self.admin_token()})
        return s, (json.loads(b) if b.strip()[:1] in (b"{", b"[") else {})

    def create_user(self):
        s, _ = self.admin("POST", "/users", {"username": USERNAME, "enabled": True, "emailVerified": True, "email": "aigw-user@example.invalid",
                                             "firstName": "Aigw", "lastName": "Tester",
                                             "credentials": [{"type": "password", "value": self.user_password, "temporary": False}]})
        if s not in (201, 409):
            raise RuntimeError(f"creating the test user failed (HTTP {s})")
        existed = s == 409                      # a Keycloak that is already running (KEYCLOAK_URL): new password for the same user
        s, users = self.admin("GET", f"/users?username={USERNAME}&exact=true")
        self.user_id = users[0]["id"]
        if existed:
            self.admin("PUT", f"/users/{self.user_id}/reset-password", {"type": "password", "value": self.user_password, "temporary": False})

    def set_realm(self, **attrs):
        s, _ = self.admin("PUT", "", attrs)
        return s

    def logout_user(self):
        """Ends the user's SSO sessions (what an admin's 'sign out' does). Offline sessions are separate."""
        s, _ = self.admin("POST", f"/users/{self.user_id}/logout")
        return s

    def sessions(self):
        """(SSO sessions, offline sessions) of the user across clients, counted."""
        s, clients = self.admin("GET", "/clients?clientId=aigw-cli")
        s2, sso = self.admin("GET", f"/users/{self.user_id}/sessions")
        s3, off = self.admin("GET", f"/users/{self.user_id}/offline-sessions/{clients[0]['id']}")
        return len(sso) if isinstance(sso, list) else -1, len(off) if isinstance(off, list) else -1

    # ---------------------------------------------------------------- the user's side of a sign-in
    def browse(self, url):
        """A minimal browser: follow redirects by hand with a cookie dict (Keycloak marks its cookies Secure even on
        http://127.0.0.1, which http.cookiejar would not send back), fill in the Keycloak login form with the test
        user's credentials when one shows up, and return the text of the last page."""
        cookies = {}
        form = None
        text = ""
        for _ in range(12):
            u = urllib.parse.urlsplit(url)
            c = http.client.HTTPConnection(u.hostname, u.port, timeout=30)
            headers = {"Cookie": "; ".join(f"{k}={v}" for k, v in cookies.items())}
            body = None
            if form is not None:
                body = urllib.parse.urlencode(form)
                headers["Content-Type"] = "application/x-www-form-urlencoded"
            c.request("POST" if form is not None else "GET", u.path + ("?" + u.query if u.query else ""), body=body, headers=headers)
            r = c.getresponse()
            page = r.read().decode("utf-8", "replace")
            for k, v in r.getheaders():
                if k.lower() == "set-cookie":
                    name, _, rest = v.partition("=")
                    value = rest.split(";")[0]
                    if "Max-Age=0" in v or value == "":
                        cookies.pop(name, None)
                    else:
                        cookies[name] = value
            form = None
            if r.status in (301, 302, 303, 307):
                url = urllib.parse.urljoin(url, r.getheader("Location"))
                continue
            text = re.sub(r"\s+", " ", re.sub(r"<[^>]+>", " ", html.unescape(page))).strip()
            m = re.search(r'<form[^>]*id="kc-form-login"[^>]*action="([^"]+)"', page) or re.search(r'<form[^>]*action="([^"]+)"[^>]*id="kc-form-login"', page)
            if "Invalid username or password" in text:
                raise RuntimeError("Keycloak refused the test user's credentials")
            if m:
                url = urllib.parse.urljoin(url, html.unescape(m.group(1)))
                form = {"username": USERNAME, "password": self.user_password, "credentialId": ""}
                continue
            # the device grant always asks the user to grant access: press "Yes"
            m = re.search(r'<form[^>]*action="([^"]*login-actions/consent[^"]*)"', page)
            code = re.search(r'name="code"\s+value="([^"]*)"', page)
            if not m:
                return text
            url = urllib.parse.urljoin(url, html.unescape(m.group(1)))
            form = {"accept": "Yes", "code": code.group(1) if code else ""}
        return text

    def approve_device(self, verification_url):
        """The user's side of a device sign-in: open the verification page (its URL carries the user code) and sign in
        as the test user. Keycloak's own device and login pages are exercised; the admin API is not used for the approval."""
        return self.browse(verification_url)

    def approve_pkce(self, authorization_url):
        """The same for the browser flow: Keycloak redirects to the client's loopback listener at the end, which this
        follows, so the client gets its code."""
        return self.browse(authorization_url)
