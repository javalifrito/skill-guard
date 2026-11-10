#!/usr/bin/env python3
"""Estimate-vs-actual cost log and recalibration (CARD-SPEC §9). Stdlib only, no network.
Usage:
  python3 -I calibrate.py record --skill NAME --source URL@SHA --est-audit N --est-fix N
         [--transcript PATH --audit-start ISO --audit-end ISO [--fix-start ISO --fix-end ISO]] [--log F]
  python3 -I calibrate.py fit [--log F] [--cal F]
Files default to <skill-dir>/cost-log.jsonl and <skill-dir>/calibration.json (skill-dir = parent of scripts/).
From the transcript only each assistant line's timestamp and message.usage numbers are read; nothing else is kept.
Actual = input + cache_creation + output tokens; cache_read is logged separately and never compared.
"""
import datetime, json, os, statistics, sys

BASE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..")
USAGE = ("input_tokens", "cache_creation_input_tokens", "output_tokens", "cache_read_input_tokens")


def opt(a, name, default=None):
    return a[a.index(name) + 1] if name in a and a.index(name) + 1 < len(a) else default


def ts(s):
    d = datetime.datetime.fromisoformat(str(s).replace("Z", "+00:00"))
    return d if d.tzinfo else d.replace(tzinfo=datetime.timezone.utc)


def window_usage(path, start, end):
    """(actual, cache_read) summed over assistant entries with start <= timestamp <= end."""
    lo, hi = ts(start), ts(end)
    act = cr = 0
    with open(path, encoding="utf-8", errors="replace") as fh:
        for line in fh:
            try:
                o = json.loads(line)
                msg = o.get("message") or {}
                if o.get("type") != "assistant" and msg.get("role") != "assistant":
                    continue
                t = ts(o["timestamp"])
                u = msg.get("usage") or {}
            except (ValueError, KeyError, TypeError, AttributeError):
                continue
            if lo <= t <= hi:
                n = [int(u.get(k) or 0) for k in USAGE]
                act += n[0] + n[1] + n[2]
                cr += n[3]
    return act, cr


def read_json(path, default):
    try:
        with open(path, encoding="utf-8") as fh:
            return json.load(fh)
    except (OSError, ValueError):
        return default


def record(a):
    log = opt(a, "--log", os.path.join(BASE, "cost-log.jsonl"))
    cal = read_json(opt(a, "--cal", os.path.join(BASE, "calibration.json")), {})
    try:
        e = {"date": datetime.date.today().isoformat(), "skill": opt(a, "--skill"), "source": opt(a, "--source"),
             "est_audit": int(opt(a, "--est-audit")), "est_fix": int(opt(a, "--est-fix", 0)),
             "act_audit": None, "act_fix": None, "cache_read_audit": None, "cache_read_fix": None,
             "factor_audit": cal.get("audit", 1.0), "factor_fix": cal.get("fix", 1.0)}
        tr = opt(a, "--transcript")
        if tr:
            if opt(a, "--audit-start") and opt(a, "--audit-end"):
                e["act_audit"], e["cache_read_audit"] = window_usage(tr, opt(a, "--audit-start"), opt(a, "--audit-end"))
            if opt(a, "--fix-start") and opt(a, "--fix-end"):
                e["act_fix"], e["cache_read_fix"] = window_usage(tr, opt(a, "--fix-start"), opt(a, "--fix-end"))
    except (TypeError, ValueError, OSError) as ex:
        sys.stderr.write(f"calibrate.py record: bad input: {ex}\n"); sys.exit(2)
    with open(log, "a", encoding="utf-8") as fh:
        fh.write(json.dumps(e, separators=(",", ":")) + "\n")
    print("logged:", json.dumps({k: e[k] for k in ("skill", "est_audit", "act_audit", "est_fix", "act_fix")}))


def mape(pairs, f):
    return sum(abs(r * f - act) / act for r, act in pairs) / len(pairs)


def fit(a):
    log = opt(a, "--log", os.path.join(BASE, "cost-log.jsonl"))
    calp = opt(a, "--cal", os.path.join(BASE, "calibration.json"))
    cur = read_json(calp, {})
    rows = []
    try:
        with open(log, encoding="utf-8") as fh:
            rows = [json.loads(l) for l in fh if l.strip()]
    except (OSError, ValueError):
        pass
    withact = [r for r in rows if r.get("act_audit") is not None or r.get("act_fix") is not None]
    if len(withact) < 5:
        print(f"need >=5 logged audits with actuals, have {len(withact)}: kept current calibration"); return
    new, adopted = dict(cur), False
    for comp in ("audit", "fix"):
        pairs = []  # (raw estimate, actual); raw = logged estimate with the factor applied at the time removed
        for r in withact:
            est, act, fac = r.get(f"est_{comp}"), r.get(f"act_{comp}"), r.get(f"factor_{comp}") or 1.0
            if est and act:
                pairs.append((est / fac, act))
        if len(pairs) < 5:
            print(f"{comp}: {len(pairs)} usable samples (<5), unchanged"); continue
        f = min(2.0, max(0.5, statistics.median(act / raw for raw, act in pairs)))
        before, after = mape(pairs, cur.get(comp, 1.0)), mape(pairs, f)
        print(f"{comp}: factor {cur.get(comp, 1.0):.2f} -> {f:.2f}; mean abs error {before:.1%} -> {after:.1%}")
        if after < before:
            new[comp], adopted = round(f, 3), True
    if adopted:
        with open(calp, "w", encoding="utf-8") as fh:
            json.dump(new, fh, indent=1)
        print("wrote", os.path.basename(calp))
    else:
        print("kept current calibration")


def main():
    a = sys.argv[1:]
    if not a or a[0] not in ("record", "fit"):
        print(__doc__); sys.exit(64)
    (record if a[0] == "record" else fit)(a[1:])


if __name__ == "__main__":
    main()
