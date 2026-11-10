#!/usr/bin/env python3
"""Dev tool: maintain tests/fixtures/attack-bundle.json (deliberately malicious scanner samples, stored encoded).
Usage: python3 -I -B fixture_bundle.py pack <set> <dir> [--bundle <file>]   add/replace a set from a directory
       python3 -I -B fixture_bundle.py list [--bundle <file>]               print set + relpaths (never contents)
Format: {"_note": ..., "format": "zlib+base64", "sets": {"<set>": base64(zlib(json {relpath: utf8 text}))}}
Decode only in memory; never write decoded attack text to disk. Stdlib only.
"""
import base64, json, os, sys, zlib

BUNDLE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "tests", "fixtures", "attack-bundle.json")
NOTE = ("Scanner test samples (deliberately malicious, inert, never executable). "
        "Encoded so no plain attack line is on disk. Decode only in memory.")


def decode(blob):
    return json.loads(zlib.decompress(base64.b64decode(blob)).decode("utf-8"))


def encode(files):
    return base64.b64encode(zlib.compress(json.dumps(files, sort_keys=True).encode("utf-8"), 9)).decode("ascii")


def load(bundle_path, set=None):
    """-> {set: {relpath: text}} (only `set` when given)."""
    with open(bundle_path, encoding="utf-8") as fh:
        sets = json.load(fh)["sets"]
    return {k: decode(v) for k, v in sets.items() if set in (None, k)}


def read_dir(d):
    out = {}
    for root, dirs, files in os.walk(d):
        dirs[:] = sorted(x for x in dirs if x not in {".git", "__pycache__"})
        for n in sorted(files):
            p = os.path.join(root, n)
            with open(p, "rb") as fh:
                out[os.path.relpath(p, d).replace(os.sep, "/")] = fh.read().decode("utf-8")
    return out


def main(argv):
    path = BUNDLE
    if "--bundle" in argv:
        i = argv.index("--bundle"); path = argv[i + 1]; argv = argv[:i] + argv[i + 2:]
    if argv[:1] == ["pack"] and len(argv) == 3:
        try:
            with open(path, encoding="utf-8") as fh:
                data = json.load(fh)
        except OSError:
            data = {"_note": NOTE, "format": "zlib+base64", "sets": {}}
        files = read_dir(argv[2])
        data["sets"][argv[1]] = encode(files)
        data["sets"] = dict(sorted(data["sets"].items()))
        with open(path, "w", encoding="utf-8") as fh:
            json.dump(data, fh, indent=1); fh.write("\n")
        print(f"packed {argv[1]}: {len(files)} files")
    elif argv[:1] == ["list"] and len(argv) == 1:
        for s, files in load(path).items():
            print(s + ":", ", ".join(sorted(files)))
    else:
        print(__doc__); return 64
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
