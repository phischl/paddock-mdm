"""Builds and checks the gitleaks configuration of `make scan-secrets` and `make scan-secrets-diff` (ADR 0026).

child <repository config> <default path> <out> <patterns out>
    Parses the repository's .gitleaks.toml, refuses everything outside a closed whitelist and writes the child
    configuration: `[extend] path = <default path>` and the repository's allowlists. Nothing of the input is copied
    verbatim, so case folding or string tricks in the input cannot change what gitleaks reads. Every `paths` and
    `regexes` entry goes to <patterns out> as a JSON array for gitleaks-patterns.go, which checks it with Go's regexp.
    An allowlist with condition = "AND" and paths must name targetRules (ADR 0027).
patterns <patterns> <verdicts>
    gitleaks-patterns.go gave one passing verdict per pattern, in order; anything else refuses the configuration.
verify-default <stripped default>
    The stripped default parses, has rules and keeps no paths in its global allowlist.
canary <report.json> <path>...
    The gitleaks JSON report of the canary run names every <path>.
"""

import json
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
        if key in CHOICES and value not in CHOICES[key]:
            raise Refused(f"allowlists[{i}].{key} is not one of {', '.join(CHOICES[key])}")
    # gitleaks' directory scan skips a file as soon as the path of a global allowlist matches, ignoring the AND
    # condition (gitleaks/gitleaks#2227); targetRules makes the allowlist rule-scoped, which that pre-filter leaves out.
    if table.get("condition") == "AND" and "paths" in table and not table.get("targetRules"):
        raise Refused(
            f'allowlists[{i}] has condition = "AND" with paths but no targetRules; gitleaks\' directory scan would skip'
            " the whole file by path alone, without its regexes (ADR 0027)"
        )


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


def patterns_of(config):
    return [p for table in config.get("allowlists", []) for key in PATTERNS for p in table.get(key, [])]


def child(repo_path, default_path, out_path, patterns_path):
    config = load(repo_path)
    check(config)
    text = emit(config, default_path)
    expected = {k: v for k, v in config.items() if k != "extend"}
    expected["extend"] = {"path": default_path}
    if tomllib.loads(text) != expected:
        raise Refused("the written child configuration does not read back as the repository configuration")
    with open(out_path, "w", encoding="utf-8") as f:
        f.write(text)
    with open(patterns_path, "w", encoding="utf-8") as f:
        json.dump(patterns_of(config), f)


def patterns(patterns_path, verdicts_path):
    # The check fails closed: a missing, short, reordered or unreadable verdict list refuses the configuration just
    # like a refused pattern.
    try:
        with open(patterns_path, encoding="utf-8") as f:
            wanted = json.load(f)
        with open(verdicts_path, encoding="utf-8") as f:
            verdicts = [json.loads(line) for line in f if line.strip()]
    except (OSError, ValueError) as e:
        raise Refused(f"cannot read the pattern check: {e}") from e
    if len(verdicts) != len(wanted):
        raise Refused(f"the pattern check returned {len(verdicts)} verdicts for {len(wanted)} patterns")
    for i, (pattern, v) in enumerate(zip(wanted, verdicts)):
        if not isinstance(v, dict) or v.get("index") != i or v.get("pattern") != pattern:
            raise Refused(f"the pattern check returned a verdict that does not belong to pattern {i}")
        if v.get("ok") is not True:
            raise Refused(f"the pattern {pattern!r} {v.get('why') or 'was refused'}")


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
        if len(argv) == 5 and argv[0] == "child":
            child(*argv[1:])
        elif len(argv) == 3 and argv[0] == "patterns":
            patterns(argv[1], argv[2])
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
