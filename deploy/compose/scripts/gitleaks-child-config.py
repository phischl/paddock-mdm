"""Builds and checks the gitleaks configuration of `make scan-secrets` and `make scan-secrets-diff` (ADR 0026).

child <repository config> <default path> <out>
    Parses the repository's .gitleaks.toml, refuses everything outside a closed whitelist and writes the child
    configuration: `[extend] path = <default path>` and the repository's allowlists. Nothing of the input is copied
    verbatim, so case folding or string tricks in the input cannot change what gitleaks reads.
verify-default <stripped default>
    The stripped default parses, has rules and keeps no paths in its global allowlist.
canary <report.json> <path>...
    The gitleaks JSON report of the canary run names every <path>.
"""

import json
import re
import sys

if sys.version_info < (3, 11):
    sys.exit("gitleaks-child-config: python 3.11 or later is required (tomllib)")

import tomllib  # noqa: E402 - the version check above must run first

# stopwords are left out on purpose: gitleaks matches them as case-insensitive substrings of the secret, so a short
# word such as "kia" or "live" silently disables whole rules (ADR 0026, amendment 2026-10-12).
STRING_LISTS = ("paths", "regexes", "commits", "targetRules")
PATTERNS = ("paths", "regexes")
CHOICES = {"condition": ("AND", "OR"), "regexTarget": ("match", "secret", "line")}
ALLOWLIST_KEYS = ("description", "condition", *STRING_LISTS, "regexTarget")


class Refused(Exception):
    """The configuration is outside the whitelist."""


def load(path):
    try:
        with open(path, "rb") as f:
            return tomllib.load(f)
    except (OSError, tomllib.TOMLDecodeError) as e:
        raise Refused(f"cannot parse {path}: {e}") from e


def is_string_list(value):
    return isinstance(value, list) and all(isinstance(v, str) for v in value)


def check_pattern(where, pattern):
    # Python's re is close enough to Go's RE2 to tell whether a pattern can match the empty string; a pattern Python
    # cannot compile (an RE2-only construct such as \pL) is refused rather than guessed.
    try:
        compiled = re.compile(pattern)
    except (re.error, RecursionError, OverflowError) as e:
        raise Refused(f"{where} holds {pattern!r}, which Python's re cannot compile ({e}); write it without "
                      "RE2-only constructs") from e
    if compiled.search("") is not None:
        raise Refused(f"{where} holds {pattern!r}, which is empty or matches the empty string, so it would match "
                      "everything")


def check_allowlist(i, table):
    if not isinstance(table, dict):
        raise Refused(f"allowlists[{i}] is not a table")
    for key, value in table.items():
        if key not in ALLOWLIST_KEYS:
            raise Refused(f"allowlists[{i}] has the key {key!r}; allowed are {', '.join(ALLOWLIST_KEYS)}")
        if key == "description" and not isinstance(value, str):
            raise Refused(f"allowlists[{i}].description is not a string")
        if key in STRING_LISTS and not is_string_list(value):
            raise Refused(f"allowlists[{i}].{key} is not a list of strings")
        if key in PATTERNS and not value:
            raise Refused(f"allowlists[{i}].{key} is an empty list")
        if key in PATTERNS:
            for pattern in value:
                check_pattern(f"allowlists[{i}].{key}", pattern)
        if key in CHOICES and value not in CHOICES[key]:
            raise Refused(f"allowlists[{i}].{key} is not one of {', '.join(CHOICES[key])}")


def check(config):
    for key in config:
        if key not in ("title", "extend", "allowlists"):
            raise Refused(f"the top-level key {key!r} is not allowed; allowed are title, extend and allowlists")
    if "title" in config and not isinstance(config["title"], str):
        raise Refused("title is not a string")
    if "extend" in config:
        extend = config["extend"]
        if not isinstance(extend, dict) or set(extend) != {"useDefault"} or extend["useDefault"] is not True:
            raise Refused("extend must be exactly {useDefault = true}; path, url and disabledRules are not allowed")
    allowlists = config.get("allowlists", [])
    if not isinstance(allowlists, list):
        raise Refused("allowlists is not an array of tables")
    for i, table in enumerate(allowlists):
        check_allowlist(i, table)


def basic(value):
    # json.dumps escapes quotes, backslashes and control characters the way TOML basic strings read them; DEL is the
    # one character TOML also requires escaped.
    return json.dumps(value, ensure_ascii=False).replace("\x7f", "\\u007f")


def emit(config, default_path):
    lines = []
    if "title" in config:
        lines.append(f"title = {basic(config['title'])}")
    lines += ["[extend]", f"path = {basic(default_path)}"]
    for table in config.get("allowlists", []):
        lines += ["", "[[allowlists]]"]
        for key in ALLOWLIST_KEYS:
            if key not in table:
                continue
            value = table[key]
            text = "[" + ", ".join(basic(v) for v in value) + "]" if isinstance(value, list) else basic(value)
            lines.append(f"{key} = {text}")
    return "\n".join(lines) + "\n"


def child(repo_path, default_path, out_path):
    config = load(repo_path)
    check(config)
    text = emit(config, default_path)
    expected = {k: v for k, v in config.items() if k != "extend"}
    expected["extend"] = {"path": default_path}
    if tomllib.loads(text) != expected:
        raise Refused("the written child configuration does not read back as the repository configuration")
    with open(out_path, "w", encoding="utf-8") as f:
        f.write(text)


def verify_default(path):
    config = load(path)
    rules = config.get("rules")
    if not isinstance(rules, list) or not rules:
        raise Refused(f"{path} has no rules")
    for key, value in config.items():
        if key.lower() == "paths":
            raise Refused(f"{path} has a top-level {key!r} key")
        if key.lower() not in ("allowlist", "allowlists"):
            continue
        for table in value if isinstance(value, list) else [value]:
            if isinstance(table, dict) and any(k.lower() == "paths" for k in table):
                raise Refused(f"{path} keeps paths in its global {key!r}")


def canary(report_path, paths):
    try:
        with open(report_path, encoding="utf-8") as f:
            found = {finding.get("File") for finding in json.load(f)}
    except (OSError, ValueError, AttributeError, TypeError) as e:
        raise Refused(f"cannot read the canary report: {e}") from e
    missing = [p for p in paths if p not in found]
    if missing:
        raise Refused(f"the canary was not reported under {', '.join(missing)}")


def main(argv):
    try:
        if len(argv) == 4 and argv[0] == "child":
            child(*argv[1:])
        elif len(argv) == 2 and argv[0] == "verify-default":
            verify_default(argv[1])
        elif len(argv) >= 3 and argv[0] == "canary":
            canary(argv[1], argv[2:])
        else:
            sys.exit(__doc__)
    except Refused as e:
        sys.exit(f"gitleaks-child-config: {e}")


if __name__ == "__main__":
    main(sys.argv[1:])
