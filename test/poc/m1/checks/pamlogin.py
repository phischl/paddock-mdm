#!/usr/bin/env python3
"""Runs pamtester inside a test VM (over SSH with a pseudo terminal) and answers the PAM conversation like a user
at the GDM greeter would: approves the Authentik device code from the host (password + TOTP via akflow.py),
types a Hello PIN or a local password. Prints a timestamped transcript (secrets are never echoed) and exits with
pamtester's exit code.

Usage: pamlogin.py <ssh-port> <service> <user> <operation>... [--pin PIN] [--password PW] [--approve USER]
       [--timeout SECONDS] [--once]
  --approve USER  approve a device code as this Authentik user (default: the login user); "none" to never approve
"""

import argparse
import datetime
import os
import re
import select
import subprocess
import sys
import time

POC_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def ts():
    return datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"


def log(msg):
    print("[%s] %s" % (ts(), msg), flush=True)


# Prompt patterns (lower-cased match) -> what to send. Order matters: the first match wins.
def responses(args):
    return [
        (re.compile(r"(confirm|repeat|again).*pin.*[:>]\s*$"), "pin"),
        (re.compile(r"(new|set up|setup|choose|create|enroll).*pin.*[:>]\s*$"), "pin"),
        (re.compile(r"pin.*[:>]\s*$"), "pin"),
        (re.compile(r"password.*[:>]\s*$"), "password"),
    ]


def main():
    p = argparse.ArgumentParser()
    p.add_argument("port")
    p.add_argument("service")
    p.add_argument("user")
    p.add_argument("ops", nargs="+")
    p.add_argument("--pin")
    p.add_argument("--password")
    p.add_argument("--approve")
    p.add_argument("--timeout", type=int, default=150)
    p.add_argument("--once", action="store_true", help="answer only the first prompt, then stop (exit 4)")
    args = p.parse_args()
    approve_as = args.approve or args.user

    key = os.path.join(POC_DIR, "..", "..", "vms", "virtualbox", ".secrets", "id_ed25519")
    cmd = ["ssh", "-tt", "-i", key, "-o", "IdentitiesOnly=yes", "-o", "StrictHostKeyChecking=no",
           "-o", "UserKnownHostsFile=/dev/null", "-o", "LogLevel=ERROR", "-p", args.port, "paddock@127.0.0.1",
           "sudo pamtester -v %s %s %s; echo PAMTESTER_EXIT=$?" % (args.service, args.user, " ".join(args.ops))]
    log("start: pamtester %s %s %s" % (args.service, args.user, " ".join(args.ops)))
    proc = subprocess.Popen(cmd, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, bufsize=0)
    buf, line, approved, deadline = "", "", False, time.time() + args.timeout
    rules = responses(args)
    exit_code = None
    answered = 0
    while time.time() < deadline:
        ready, _, _ = select.select([proc.stdout], [], [], 1.0)
        if not ready:
            if proc.poll() is not None:
                break
            # A pending prompt that no rule answered.
            continue
        chunk = os.read(proc.stdout.fileno(), 4096).decode(errors="replace")
        if not chunk:
            break
        buf += chunk
        line += chunk
        while "\n" in line:
            out, line = line.split("\n", 1)
            out = out.rstrip("\r")
            if out.strip():
                log("vm: " + out)
            m = re.search(r"PAMTESTER_EXIT=(\d+)", out)
            if m:
                exit_code = int(m.group(1))
        # Device code: Authentik user codes are numeric; the verification URL may carry it as ?code=.
        code = re.search(r"(?:code=|code[:\s]+)(\d{6,})", buf, re.IGNORECASE)
        if code and not approved:
            approved = True
            if approve_as != "none":
                log("host: approving device code %s as %s" % (code.group(1), approve_as))
                res = subprocess.run([os.path.join(POC_DIR, "authentik-setup.sh"), "approve", approve_as, code.group(1)],
                                     capture_output=True, text=True)
                for l in (res.stdout + res.stderr).splitlines():
                    log("host: " + l)
            else:
                log("host: not approving device code %s" % code.group(1))
        pending = line.strip().lower()
        for rx, what in rules:
            if pending and rx.search(pending):
                if args.once and answered:
                    log("vm: %s <not answered: --once>" % line.strip())
                    proc.kill()
                    proc.wait()
                    sys.exit(4)
                answered += 1
                value = getattr(args, what)
                if value is None:
                    log("prompt %r needs --%s; aborting" % (line.strip(), what))
                    proc.kill()
                    sys.exit(3)
                log("vm: %s <%s sent>" % (line.strip(), what))
                proc.stdin.write((value + "\n").encode())
                line = ""
                break
    else:
        log("timeout after %ds" % args.timeout)
        proc.kill()
    proc.wait()
    log("pamtester exit=%s" % exit_code)
    sys.exit(exit_code if exit_code is not None else 2)


if __name__ == "__main__":
    main()
