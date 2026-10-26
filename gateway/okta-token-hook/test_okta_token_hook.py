"""Offline tests for okta_token_hook.py. Payloads are shaped per what could be confirmed
from Okta's docs/forum (data.context.user, data.access.claims); `groups` placement and
`data.context.user.profile.login` are GUESSED (unconfirmed)."""
import http.client
import json
import os
import tempfile
import threading
import time
import sys
import unittest
from http.server import ThreadingHTTPServer

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import okta_token_hook as h  # noqa: E402

SECRET = "Basic dGVzdDp0ZXN0"  # dummy
MAPPING = json.load(open(os.path.join(os.path.dirname(os.path.abspath(__file__)),
                                      "mapping.example.json")))


def payload(groups=None, via="claims", login="user@example.com"):
    p = {"eventType": "com.okta.oauth2.tokens.transform",
         "data": {"context": {"user": {"id": "00u1abc", "profile": {"login": login}},
                              "protocol": {"request": {"grant_type": "authorization_code"}}},
                  "access": {"claims": {"sub": login, "iss": "https://<org>.okta.com/oauth2/default",
                                        "aud": "api://default"},
                             "scopes": {}}}}
    if groups is not None:
        if via == "claims":
            p["data"]["access"]["claims"]["groups"] = groups
        else:
            p["data"]["context"]["user"]["groups"] = groups
    return p


class Base(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.path = os.path.join(self.tmp.name, "m.json")
        self.write(MAPPING)
        self.mapping = h.Mapping(self.path)
        self.srv = ThreadingHTTPServer(("127.0.0.1", 0), h.make_handler(self.mapping, SECRET, "Authorization"))
        self.srv.daemon_threads = True
        threading.Thread(target=self.srv.serve_forever, daemon=True).start()

    def tearDown(self):
        self.srv.shutdown()
        self.srv.server_close()
        self.tmp.cleanup()

    def write(self, doc):
        with open(self.path, "w") as f:
            json.dump(doc, f)

    def post(self, body, auth=SECRET, raw=False):
        c = http.client.HTTPConnection("127.0.0.1", self.srv.server_port, timeout=5)
        hdr = {"Content-Type": "application/json"}
        if auth is not None:
            hdr["Authorization"] = auth
        c.request("POST", "/", body if raw else json.dumps(body), hdr)
        r = c.getresponse()
        data = r.read()
        c.close()
        return r.status, json.loads(data)

    @staticmethod
    def ops(resp):
        cmd = resp["commands"][0]
        assert cmd["type"] == "com.okta.access.patch"
        return {o["path"]: o for o in cmd["value"]}


class Tests(Base):
    def test_auth(self):
        self.assertEqual(self.post(payload(["aigw-eng"]), auth="wrong")[0], 401)
        self.assertEqual(self.post(payload(["aigw-eng"]), auth=None)[0], 401)
        self.assertEqual(self.post(payload(["aigw-eng"]))[0], 200)

    def test_nested_and_arrays(self):
        _, r = self.post(payload(["aigw-eng"]))
        ops = self.ops(r)
        d = ops["/claims/defaults"]["value"]
        self.assertIsInstance(d, dict)
        self.assertEqual(d["metadata"]["team"], "eng")
        self.assertIn("config_slug", d)
        ul = ops["/claims/usage_limits"]["value"]
        self.assertIsInstance(ul, list)
        self.assertEqual(ul[0]["credit_limit"], 100)
        self.assertEqual(ops["/claims/portkey_workspace"]["op"], "add")

    def test_email_from_login(self):
        _, r = self.post(payload(["aigw-eng"], login="a@example.com"))
        self.assertEqual(self.ops(r)["/claims/email_id"]["value"], "a@example.com")
        _, r = self.post(payload(["aigw-research"]))
        self.assertNotIn("/claims/email_id", self.ops(r))

    def test_first_match_wins(self):
        _, r = self.post(payload(["aigw-eng", "aigw-research"]))  # research rule is first in file
        self.assertEqual(self.ops(r)["/claims/defaults"]["value"]["metadata"]["team"], "research")

    def test_groups_fallback_location(self):
        _, r = self.post(payload(["aigw-eng"], via="user"))
        self.assertIn("/claims/portkey_workspace", self.ops(r))

    def test_no_match_no_commands(self):
        self.assertEqual(self.post(payload(["other"])), (200, {}))
        self.assertEqual(self.post(payload()), (200, {}))

    def test_default_rule(self):
        doc = dict(MAPPING, default={"claims": {"portkey_oid": "o", "portkey_workspace": "w"}})
        self.write(doc)
        self.mapping.load()
        _, r = self.post(payload(["other"]))
        self.assertEqual(self.ops(r)["/claims/portkey_workspace"]["value"], "w")

    def test_malformed_and_odd_shapes(self):
        self.assertEqual(self.post("{not json", raw=True), (200, {}))
        self.assertEqual(self.post([1, 2]), (200, {}))
        self.assertEqual(self.post({"data": "x"}), (200, {}))

    def test_size_cap(self):
        c = http.client.HTTPConnection("127.0.0.1", self.srv.server_port, timeout=5)
        c.request("POST", "/", "x", {"Authorization": SECRET, "Content-Length": str(h.MAX_BODY + 1)})
        self.assertEqual(c.getresponse().status, 413)

    def test_reload_on_mtime(self):
        doc = json.loads(json.dumps(MAPPING))
        doc["rules"][1]["claims"]["portkey_workspace"] = "changed"
        self.write(doc)
        os.utime(self.path, (time.time() + 5, time.time() + 5))
        _, r = self.post(payload(["aigw-eng"]))
        self.assertEqual(self.ops(r)["/claims/portkey_workspace"]["value"], "changed")

    def test_bad_reload_keeps_old(self):
        with open(self.path, "w") as f:
            f.write("{broken")
        os.utime(self.path, (time.time() + 9, time.time() + 9))
        _, r = self.post(payload(["aigw-eng"]))
        self.assertIn("/claims/portkey_oid", self.ops(r))

    def test_forbidden_claim_rejected(self):
        self.write({"rules": [{"group": "g", "claims": {"sub": "x"}}]})
        with self.assertRaises(ValueError):
            h.Mapping(self.path)

    def test_log_has_no_secret_or_user_id(self):
        with self.assertLogs("okta_token_hook", "INFO") as cm:
            self.post(payload(["aigw-eng"]))
            self.post(payload(["aigw-eng"]), auth="wrong-secret-value")
        out = "\n".join(cm.output)
        self.assertNotIn(SECRET, out)
        self.assertNotIn("wrong-secret-value", out)
        self.assertNotIn("00u1abc", out)
        self.assertIn("rule=aigw-eng", out)


if __name__ == "__main__":
    unittest.main()
