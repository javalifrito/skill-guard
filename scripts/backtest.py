#!/usr/bin/env python3
"""Backtest an updated scan.py against the previous one (CARD-SPEC §10).
Usage: python3 -I -B backtest.py --old <old scan.py> --new <new scan.py> --targets <dir>... [--truth <fixtures dir>...] [--card <card.py>]
Truth/target dirs may also be encoded test samples: bundle:<bundle.json>#<set> (scanned in memory via scan.py --bundle;
  expected.json is read from inside the set).
Truth dirs: every entry of <dir>/expected.json ("file:line" -> {min_severity, rule_id}) must be found by NEW at >= that
  severity, and the exit code of NEW must equal the OLD one. Dirs without expected.json (e.g. the malicious sample) are
  checked for: same exit code, and no CRITICAL/HIGH finding of OLD lost or lowered.
Real targets: lists every finding that disappeared or dropped a level (rule_id, file:line, old->new, reason, snippet),
  counts per severity old->new, and the card size in tokens (card.py output chars / 4) for OLD vs NEW output.
Exit 1 on any truth FAIL. Stdlib only. Reads files only; scanners never execute the targets.
"""
import argparse, base64, json, os, subprocess, sys, zlib
from collections import Counter

ORDER = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "INFO": 0}


def bundle_spec(t):
    """'bundle:<path>#<set>' -> (path, set) else None."""
    if t.startswith("bundle:") and "#" in t:
        p, _, s = t[7:].rpartition("#")
        return p, s
    return None


def bundle_file(spec, rel):
    """Text of <rel> inside the bundle set, or None. Decoded in memory only."""
    with open(spec[0], encoding="utf-8") as fh:
        blob = json.load(fh)["sets"][spec[1]]
    return json.loads(zlib.decompress(base64.b64decode(blob)).decode("utf-8")).get(rel)


def run_scan(scan, target):
    b = bundle_spec(target)
    cmd = [sys.executable, "-I", "-B", scan] + ([b[0], "--bundle", "--set=" + b[1]] if b else [target]) + ["--json"]
    r = subprocess.run(cmd, capture_output=True, text=True, encoding="utf-8")
    try:
        return json.loads(r.stdout), r.returncode
    except ValueError:
        sys.exit(f"backtest: {scan} gave no JSON for {target} (exit {r.returncode}): {r.stderr[:200]}")


def card_tokens(card, data):
    r = subprocess.run([sys.executable, "-I", "-B", card, "-"], input=json.dumps(data), capture_output=True, text=True, encoding="utf-8")
    return len(r.stdout) // 4


def index(data):
    """(rule_id, file, line) -> finding (highest severity wins on duplicates)."""
    out = {}
    for f in data["findings"]:
        k = (f["rule_id"], f["file"], f["line"])
        if k not in out or ORDER[f["severity"]] > ORDER[out[k]["severity"]]:
            out[k] = f
    return out


def truth(old_scan, new_scan, d):
    """Returns (ok, lines)."""
    lines, ok = [], True
    new, new_exit = run_scan(new_scan, d)
    old, old_exit = run_scan(old_scan, d)
    b = bundle_spec(d)
    exp_path = os.path.join(d, "expected.json")
    exp_text = bundle_file(b, "expected.json") if b else (open(exp_path, encoding="utf-8").read() if os.path.isfile(exp_path) else None)
    if old_exit != new_exit:
        ok = False
        lines.append(f"  FAIL exit code changed {old_exit} -> {new_exit}")
    else:
        lines.append(f"  ok   exit code unchanged ({new_exit})")
    if exp_text is not None:
        exp = json.loads(exp_text)
        by_loc = {}
        for f in new["findings"]:
            by_loc.setdefault(f"{f['file']}:{f['line']}", []).append(f)
        for loc, e in exp.items():
            hits = [f for f in by_loc.get(loc, []) if f["rule_id"] == e["rule_id"]]
            best = max(hits, key=lambda f: ORDER[f["severity"]], default=None)
            if best and ORDER[best["severity"]] >= ORDER[e["min_severity"]]:
                lines.append(f"  ok   {loc} {e['rule_id']} {best['severity']} (>= {e['min_severity']})")
            else:
                ok = False
                got = best["severity"] if best else "not found"
                lines.append(f"  FAIL {loc} {e['rule_id']}: expected >= {e['min_severity']}, got {got}")
    else:
        oi, ni = index(old), index(new)
        for k, f in oi.items():
            if ORDER[f["severity"]] >= 3:
                n = ni.get(k)
                if not n or ORDER[n["severity"]] < ORDER[f["severity"]]:
                    ok = False
                    lines.append(f"  FAIL {k[1]}:{k[2]} {k[0]} {f['severity']} -> {n['severity'] if n else 'gone'}")
        if ok:
            lines.append("  ok   no CRITICAL/HIGH finding lost or lowered")
    return ok, lines


def real(old_scan, new_scan, card, d):
    old, oe = run_scan(old_scan, d)
    new, ne = run_scan(new_scan, d)
    oi, ni = index(old), index(new)
    lost = []
    for k, f in oi.items():
        n = ni.get(k)
        if n is None:
            lost.append((k, f, None, "regex tightened"))
        elif ORDER[n["severity"]] < ORDER[f["severity"]]:
            lost.append((k, f, n, n.get("reason") or "rule severity lowered"))
    gained = [(k, f) for k, f in ni.items() if k not in oi or ORDER[f["severity"]] > ORDER[oi[k]["severity"]]]
    oc, nc = Counter(f["severity"] for f in old["findings"]), Counter(f["severity"] for f in new["findings"])
    sev = " ".join(f"{s[0]}={oc.get(s, 0)}->{nc.get(s, 0)}" for s in ("CRITICAL", "HIGH", "MEDIUM", "LOW"))
    ot, nt = card_tokens(card, old), card_tokens(card, new)
    print(f"\n=== {d}")
    print(f"counts {sev} | findings {len(old['findings'])}->{len(new['findings'])} | card tokens {ot}->{nt} | exit code {oe}->{ne}")
    by_rule = Counter((k[0], f["severity"], n["severity"] if n else "gone") for k, f, n, _ in lost)
    if by_rule:
        print("removed/lowered by rule (rule_id old->new: count):")
        for (r, a, b), c in sorted(by_rule.items(), key=lambda x: -x[1]):
            print(f"  {r} {a}->{b}: {c}")
    for k, f, n, why in sorted(lost, key=lambda x: (-ORDER[x[1]["severity"]], x[0][1], x[0][2])):
        snip = (f.get("snippet") or "").replace("\n", " ")[:100]
        print(f"  - {k[0]} {k[1]}:{k[2]} {f['severity']}->{n['severity'] if n else 'gone'} [{why}] | {snip}")
    if gained:
        print(f"new or raised findings: {len(gained)}")
        for k, f in sorted(gained, key=lambda x: (-ORDER[x[1]['severity']], x[0][1], x[0][2])):
            was = oi.get(k)
            snip = (f.get("snippet") or "").replace("\n", " ")[:100]
            print(f"  + {k[0]} {k[1]}:{k[2]} {was['severity'] if was else 'none'}->{f['severity']} | {snip}")
    return len(lost), len(gained), ot, nt


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--old", required=True)
    ap.add_argument("--new", required=True)
    ap.add_argument("--targets", nargs="*", default=[])
    ap.add_argument("--truth", nargs="*", default=[])
    ap.add_argument("--card", default=None)
    a = ap.parse_args()
    card = a.card or os.path.join(os.path.dirname(os.path.abspath(a.new)), "card.py")
    failed = False
    for d in a.truth:
        print(f"=== TRUTH {d}")
        ok, lines = truth(a.old, a.new, d)
        print("\n".join(lines))
        print(f"TRUTH {'PASS' if ok else 'FAIL'}: {d}")
        failed |= not ok
    tot_lost = tot_gained = 0
    for d in a.targets:
        l, g, _, _ = real(a.old, a.new, card, d)
        tot_lost += l; tot_gained += g
    if a.targets:
        print(f"\nTOTAL removed/lowered: {tot_lost} | new/raised: {tot_gained} across {len(a.targets)} targets")
    print("RESULT: " + ("FAIL" if failed else "PASS"))
    sys.exit(1 if failed else 0)


if __name__ == "__main__":
    main()
