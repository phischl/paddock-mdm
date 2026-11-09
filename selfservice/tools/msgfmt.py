"""Compile a gettext catalog (.po) into a .mo file with the standard library only, so that building the package
needs no gettext tools: `python3 msgfmt.py <in.po> <out.mo>`.

Supports what the app's catalogs use: msgid/msgstr pairs with continuation lines and the header entry; no plurals,
no contexts. Fuzzy and untranslated entries are left out, as GNU msgfmt does.
"""

from __future__ import annotations

import ast
import os
import struct
import sys


def parse(text: str) -> dict[str, str]:
    """Return the translations of a .po text, the header under the empty msgid."""
    entries: dict[str, str] = {}
    msgid: str | None = None
    msgstr: str | None = None
    field = ""
    fuzzy = False

    def flush() -> None:
        nonlocal msgid, msgstr, fuzzy
        if msgid is not None and msgstr is not None and not fuzzy and (msgstr or msgid == ""):
            entries[msgid] = msgstr
        msgid, msgstr, fuzzy = None, None, False

    for number, raw in enumerate(text.splitlines(), 1):
        line = raw.strip()
        if line.startswith("#,") and "fuzzy" in line:
            flush()
            fuzzy = True
        elif not line or line.startswith("#"):
            continue
        elif line.startswith("msgid "):
            if msgstr is not None:
                flush()
            msgid, field = _string(line[6:], number), "id"
        elif line.startswith("msgstr "):
            if msgid is None:
                raise ValueError(f"line {number}: msgstr without msgid")
            msgstr, field = _string(line[7:], number), "str"
        elif line.startswith('"'):
            if field == "id" and msgid is not None and msgstr is None:
                msgid += _string(line, number)
            elif field == "str" and msgstr is not None:
                msgstr += _string(line, number)
            else:
                raise ValueError(f"line {number}: continuation without msgid or msgstr")
        else:
            raise ValueError(f"line {number}: unsupported syntax: {line}")
    flush()
    return entries


def _string(token: str, number: int) -> str:
    value = ast.literal_eval(token.strip())
    if not isinstance(value, str):
        raise ValueError(f"line {number}: not a string")
    return value


def compile_mo(entries: dict[str, str]) -> bytes:
    """Return the .mo of entries (format of GNU gettext, little endian, no hash table)."""
    keys = sorted(entries)
    ids = [k.encode("utf-8") for k in keys]
    strs = [entries[k].encode("utf-8") for k in keys]
    n = len(keys)
    header = 7 * 4
    ids_table = header
    strs_table = ids_table + n * 8
    data = strs_table + n * 8
    offsets: list[int] = []
    blob = b""
    for s in ids + strs:
        offsets += [len(s), data + len(blob)]
        blob += s + b"\0"
    out = struct.pack("<7I", 0x950412DE, 0, n, ids_table, strs_table, 0, data)
    out += struct.pack(f"<{4 * n}I", *offsets)
    return out + blob


def main(argv: list[str]) -> int:
    if len(argv) != 3:
        print("usage: msgfmt.py <in.po> <out.mo>", file=sys.stderr)
        return 2
    with open(argv[1], encoding="utf-8") as f:
        entries = parse(f.read())
    os.makedirs(os.path.dirname(os.path.abspath(argv[2])), exist_ok=True)
    with open(argv[2], "wb") as f:
        f.write(compile_mo(entries))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
