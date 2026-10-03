#!/usr/bin/env python3
"""Drives Authentik flows headlessly through the flow executor API (/api/v3/flows/executor/<slug>/), the way a
user would in a browser. Used by the M1 PoC to enrol TOTP with a known secret and to approve a device
authorization request (RFC 8628) with password + TOTP.

Usage:
  akflow.py enroll-totp <username>              prints the TOTP secret of a new device
  akflow.py device <username> <user_code>       approves a pending device code
  akflow.py totp <username>                     prints the current TOTP code (waits for an unused time step)

Environment: AUTH_URL (https://auth.paddock.localhost:8443), CADDY_ROOT (CA file), POC_SECRETS (password_<user>,
totp_<user>).
"""

import base64
import hashlib
import hmac
import http.cookiejar
import json
import os
import ssl
import struct
import sys
import time
import urllib.error
import urllib.parse
import urllib.request

AUTH_URL = os.environ.get("AUTH_URL", "https://auth.paddock.localhost:8443").rstrip("/")
SECRETS = os.environ["POC_SECRETS"]


def secret(name):
    with open(os.path.join(SECRETS, name)) as f:
        return f.read().strip()


def totp_now(username):
    """Returns a TOTP code for a time step not used before (Authentik rejects a replayed step)."""
    key = base64.b32decode(secret("totp_" + username).upper() + "=" * (-len(secret("totp_" + username)) % 8))
    last_file = os.path.join(SECRETS, "totp_" + username + ".last")
    last = int(open(last_file).read()) if os.path.exists(last_file) else -1
    step = int(time.time()) // 30
    if step <= last:
        time.sleep((last + 1) * 30 - time.time() + 1)
        step = int(time.time()) // 30
    with open(last_file, "w") as f:
        f.write(str(step))
    digest = hmac.new(key, struct.pack(">Q", step), hashlib.sha1).digest()
    offset = digest[-1] & 0x0F
    code = (struct.unpack(">I", digest[offset:offset + 4])[0] & 0x7FFFFFFF) % 1000000
    return "%06d" % code


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        return None


class Browser:
    def __init__(self):
        ctx = ssl.create_default_context(cafile=os.environ["CADDY_ROOT"])
        self.jar = http.cookiejar.CookieJar()
        self.opener = urllib.request.build_opener(
            urllib.request.HTTPSHandler(context=ctx),
            urllib.request.HTTPCookieProcessor(self.jar),
            NoRedirect(),
        )

    def request(self, method, url, body=None):
        data = json.dumps(body).encode() if body is not None else None
        req = urllib.request.Request(url, data=data, method=method)
        req.add_header("Accept", "application/json")
        # Django's CSRF check on authenticated HTTPS requests wants a same-origin Referer, like a browser sends.
        req.add_header("Referer", AUTH_URL + "/")
        if data is not None:
            req.add_header("Content-Type", "application/json")
        for c in self.jar:
            if c.name == "authentik_csrf":
                req.add_header("X-authentik-CSRF", c.value)
        try:
            resp = self.opener.open(req, timeout=30)
        except urllib.error.HTTPError as e:
            resp = e
        return resp.status, resp.headers, resp.read()


def run_flow(browser, page, answers):
    """Runs one flow page (/if/flow/<slug>/?query) through the executor; returns the URL it redirects to."""
    slug = page.path[len("/if/flow/"):].strip("/")
    executor = "%s/api/v3/flows/executor/%s/?%s" % (
        AUTH_URL, slug, urllib.parse.urlencode({"query": page.query}))
    method, body = "GET", None
    for _ in range(15):
        status, headers, data = browser.request(method, executor, body)
        if status == 302:
            executor = urllib.parse.urljoin(executor, headers["Location"])
            method, body = "GET", None
            continue
        if status != 200:
            raise SystemExit("flow %s: HTTP %d: %s" % (slug, status, data[:300]))
        ch = json.loads(data)
        component = ch.get("component")
        # Stage trace on stderr: evidence of which factors Authentik asked for.
        print("akflow: %s %s" % (slug, component), file=sys.stderr)
        if component == "xak-flow-redirect":
            return urllib.parse.urljoin(AUTH_URL + "/", ch["to"])
        if component == "ak-stage-access-denied":
            raise SystemExit("DENIED in flow %s: %s" % (slug, ch.get("error_message", "")))
        if component not in answers:
            raise SystemExit("flow %s: unsupported stage %s: %s" % (slug, component, json.dumps(ch)[:400]))
        answer = answers[component](ch)
        if answer is None:  # terminal stage (e.g. a success message)
            return None
        answer["component"] = component
        method, body = "POST", answer
    raise SystemExit("flow %s did not finish" % slug)


def browse(browser, url, answers):
    """Follows redirects from url, running every Authentik flow page on the way. Returns the final URL."""
    for _ in range(30):
        u = urllib.parse.urlparse(url)
        if u.path.startswith("/if/flow/"):
            url = run_flow(browser, u, answers)
            if url is None:
                return None
            continue
        status, headers, data = browser.request("GET", url)
        if status in (301, 302, 303, 307):
            url = urllib.parse.urljoin(url, headers["Location"])
            continue
        return url
    raise SystemExit("too many redirects")


def login_answers(username):
    return {
        "ak-stage-identification": lambda ch: {"uid_field": username},
        "ak-stage-password": lambda ch: {"password": secret("password_" + username)},
        "ak-stage-authenticator-validate": lambda ch: {"code": totp_now(username)},
        "ak-stage-consent": lambda ch: {"token": ch.get("token", "")},
    }


def enroll_totp(username):
    browser = Browser()
    answers = login_answers(username)
    browse(browser, AUTH_URL + "/if/flow/default-authentication-flow/", answers)
    found = {}

    def totp_stage(ch):
        query = urllib.parse.parse_qs(urllib.parse.urlparse(ch["config_url"]).query)
        found["secret"] = query["secret"][0]
        key = base64.b32decode(found["secret"] + "=" * (-len(found["secret"]) % 8))
        digest = hmac.new(key, struct.pack(">Q", int(time.time()) // 30), hashlib.sha1).digest()
        offset = digest[-1] & 0x0F
        code = (struct.unpack(">I", digest[offset:offset + 4])[0] & 0x7FFFFFFF) % 1000000
        return {"code": "%06d" % code}

    answers["ak-stage-authenticator-totp"] = totp_stage
    browse(browser, AUTH_URL + "/if/flow/default-authenticator-totp-setup/", answers)
    if "secret" not in found:
        raise SystemExit("no TOTP setup stage was shown for %s" % username)
    print(found["secret"])


def approve_device(username, user_code):
    browser = Browser()
    answers = login_answers(username)
    answers["ak-provider-oauth2-device-code"] = lambda ch: {"code": user_code}
    # The last stage of a granted device authorization; it only shows a message.
    answers["ak-provider-oauth2-device-code-finish"] = lambda ch: None
    final = browse(browser, AUTH_URL + "/device?" + urllib.parse.urlencode({"code": user_code}), answers)
    if final is not None:
        raise SystemExit("NOT APPROVED: flow ended at %s" % final)
    print("approved")


def main():
    if len(sys.argv) == 3 and sys.argv[1] == "enroll-totp":
        enroll_totp(sys.argv[2])
    elif len(sys.argv) == 4 and sys.argv[1] == "device":
        approve_device(sys.argv[2], sys.argv[3])
    elif len(sys.argv) == 3 and sys.argv[1] == "totp":
        print(totp_now(sys.argv[2]))
    else:
        raise SystemExit(__doc__)


if __name__ == "__main__":
    main()
