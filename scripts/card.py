#!/usr/bin/env python3
"""Render the plain-language problems card from `scan.py --json` output.
Usage: python3 -I card.py <scan.json | -> [--review review.json] [--format md|text]
review.json: {"dismiss": {"file:line": "reason"}, "level": {"file:line": "MEDIUM"}, "confirmed": {"file:line": "reason"} (or a list of keys)}
A finding with confidence "suspected" (downgraded by context) gets " (suspected)" after its bullet unless the review confirms it.
Stdlib only, no network, reads files only, never executes the target. Exit 0 (2 on bad input).
Library: ../explanations.json (relative to this script).
"""
import json, math, os, sys

ORDER = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "INFO": 0}
ICON = {"CRITICAL": "🔴", "HIGH": "🟠", "MEDIUM": "🟡", "LOW": "🔵", "INFO": "⚪"}
NAME = {"CRITICAL": "Critical", "HIGH": "High", "MEDIUM": "Medium", "LOW": "Low", "INFO": "Info"}
ACTION = {
    "CRITICAL": "Do not install. Not even fixed. Block the source.",
    "HIGH": "Don't install as-is. Install only the fixed version.",
    "MEDIUM": "Install after the fix (recommended), or as-is if you accept the explained risk.",
    "LOW": "Safe to install. Fix optional.",
    "INFO": "Safe to install. Nothing to do.",
}
HEAD = {"CRITICAL": "Do not install", "HIGH": "Install only the fixed version", "MEDIUM": "Install after the fix",
        "LOW": "Safe to install", "INFO": "Safe to install"}
CATS = [("🔐", "Passwords & accounts"), ("📁", "Your private files"), ("🖥️", "Takes over your computer"),
        ("📤", "Sends your data elsewhere"), ("🎭", "Hidden tricks"), ("📢", "Ads & tracking"), ("🧨", "Unsafe code")]
CAT_ICON = dict((n, i) for i, n in CATS)
CAT_POS = {n: k for k, (_, n) in enumerate(CATS)}
# --- Cost model (CARD-SPEC §9). Duplicated in scan.py and card.py on purpose; keep both in sync.
SIZES = [(5_000, "Very Small"), (20_000, "Small"), (60_000, "Medium"), (150_000, "Large"), (float("inf"), "Very Large")]
TIER_TOK = {"Script (free)": 0, "Very Small": 200, "Small": 500}
TIER_RANK = {"Script (free)": 0, "Very Small": 1, "Small": 2, "Rewrite": 3}
FIX_OVERHEAD = 1000
_BASE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..")


def _jload(name):
    try:
        with open(os.path.join(_BASE, name), encoding="utf-8") as fh:
            return json.load(fh)
    except (OSError, ValueError):
        return {}


def size_label(t):
    return next(l for lim, l in SIZES if t < lim)


def fix_estimate(lines, lib, file_chars, text_chars, factor=1.0):
    """lines: {(file, line): {"sev": SEV, "rids": [rule_id, ...]}} (live findings only).
    Returns (tokens, kind) with kind in none|fix|rebuild. Rewrite counts once per file and covers that file's other lines."""
    if any(m["sev"] == "CRITICAL" for m in lines.values()):
        return round((2 * (text_chars // 4) + FIX_OVERHEAD) * factor), "rebuild"
    tier_of = {}
    for (fp, ln), m in lines.items():
        if m["sev"] in ("LOW", "INFO"):
            continue  # LOW-only line: fix optional, costs 0
        best = "Script (free)"
        for rid in m["rids"]:
            t = lib.get(lib.get(rid, {}).get("same_as", rid), {}).get("fix_tier", "Small")
            if TIER_RANK.get(t, 2) > TIER_RANK[best]:
                best = t
        tier_of[(fp, ln)] = best
    rewrites = {fp for (fp, ln), t in tier_of.items() if t == "Rewrite"}
    total = sum(2 * (file_chars.get(fp, 2000) // 4) for fp in rewrites)
    total += sum(TIER_TOK.get(t, 500) for (fp, ln), t in tier_of.items() if fp not in rewrites)
    return (round((total + FIX_OVERHEAD) * factor), "fix") if total else (0, "none")


def usd(tokens, model, share_in, prices):
    m = (prices.get("models") or {}).get(model)
    if not m or not tokens:
        return None
    return tokens * (share_in * m["input"] + (1 - share_in) * m["output"]) / 1e6


def fmt_usd(x):
    if x is None:
        return ""
    if x < 0.01:
        return "<$0.01"
    fl = math.floor(math.log10(x))
    s = f"{x:.{max(0, 1 - fl)}f}"
    if "." in s:
        s = s.rstrip("0").rstrip(".") if x >= 10 else s.rstrip("0")
    if x < 10:
        s = s + "0" * max(0, 2 - len(s.split(".")[1])) if "." in s else s + ".00"
    return "~$" + s


def stale_note(prices):
    try:
        import datetime
        age = (datetime.date.today() - datetime.date.fromisoformat(prices["date"])).days
        return f" (prices from {prices['date']})" if age > 90 else ""
    except (KeyError, ValueError, TypeError):
        return ""


def _cell(tokens):
    return max(1, min(10, round(10 * math.log10(max(tokens, 1000) / 1000) / math.log10(300)))) - 1


def cost_bar(audit_t, fix_t=0, kind="none", color=False):
    """10-cell log-scale gradient (1k = cell 1, 300k+ = cell 10); markers replace the cell: 🔍 audit, 🔧 fix, 🧱 rebuild."""
    a = _cell(audit_t)
    f = None
    if fix_t:
        f = _cell(fix_t)
        if f == a:
            if f < 9: f += 1
            else: a -= 1
    fm = "🧱" if kind == "rebuild" else "🔧"
    out = []
    for i in range(10):
        if i == a: out.append("🔍")
        elif i == f: out.append(fm)
        elif color:
            t = i / 9
            r, g = (int(510 * t), 200) if t < 0.5 else (255, int(200 * (2 - 2 * t)))
            out.append(f"\033[38;2;{min(r, 255)};{g};40m█\033[0m")
        else:
            out.append("🟩🟩🟩🟨🟨🟨🟧🟧🟥🟥"[i])
    return "".join(out)


def _k(t):
    return f"~{round(t / 1000) or '<1'}k" if t >= 500 else "~<1k"


def legend(audit_t, audit_usd, fix_t, kind, fix_usd, prices):
    p = lambda d: (" " + fmt_usd(d)) if d is not None else ""
    s = f"🔍 audit {_k(audit_t)} {size_label(audit_t)}{p(audit_usd)}"
    if fix_t:
        s += f" · {'🧱 rebuild' if kind == 'rebuild' else '🔧 fix'} {_k(fix_t)} {size_label(fix_t)}{p(fix_usd)}"
    else:
        s += " · fix: none needed"
    return s + stale_note(prices)


def load(path):
    try:
        return json.load(sys.stdin if path == "-" else open(path, encoding="utf-8"))
    except (OSError, ValueError) as e:
        sys.stderr.write(f"card.py: cannot read {path}: {e}\n"); sys.exit(2)


def locs(items, key=lambda f: f):
    seen = []
    for f in items:
        l = key(f)
        if l not in seen: seen.append(l)
    return seen


def fmt_locs(seen):
    shown = [f"`{l}`" for l in seen[:3]]
    return ", ".join(shown) + (f", +{len(seen) - 3} more" if len(seen) > 3 else "")


def main():
    a = sys.argv[1:]
    if not a or a[0] in ("-h", "--help"):
        print(__doc__); sys.exit(0 if a else 2)
    fmt = a[a.index("--format") + 1] if "--format" in a else "md"
    review = load(a[a.index("--review") + 1]) if "--review" in a else None
    scan = load(a[0])
    if not isinstance(scan, dict) or "findings" not in scan:
        sys.stderr.write("card.py: input is not scan.py --json output\n"); sys.exit(2)
    lib = _jload("explanations.json")
    md = fmt != "text"
    b = (lambda s: f"**{s}**") if md else (lambda s: s)

    dismiss = (review or {}).get("dismiss", {})
    relevel = (review or {}).get("level", {})
    confirmed = set((review or {}).get("confirmed", {}))
    live, checked = [], []  # checked: (loc, reason)
    for f in scan["findings"]:
        loc = f"{f['file']}:{f['line']}"
        if loc in dismiss:
            checked.append((loc, dismiss[loc])); continue
        sev = relevel.get(loc, f["severity"])
        if sev not in ORDER: sev = f["severity"]
        conf = "confirmed" if loc in confirmed else f.get("confidence", "likely")
        live.append(dict(f, sev=sev, confidence=conf, loc=f["file"] if not f["line"] else loc))
    checked = [(l, r) for l, r in {l: r for l, r in checked}.items()]
    # dismissed line count: one entry per distinct location

    counts = {s: sum(1 for f in live if f["sev"] == s) for s in ORDER}
    worst = max((f["sev"] for f in live), key=lambda s: ORDER[s], default="INFO")
    cost = scan.get("cost", {})
    audit_t = cost.get("audit_tokens", 0)
    # fix cost after review (CARD-SPEC §9): same model as scan.py, on live findings at their reviewed level
    lines = {}
    for f in live:
        m = lines.setdefault((f["file"], f["line"]), {"sev": f["sev"], "rids": []})
        if ORDER[f["sev"]] > ORDER[m["sev"]]: m["sev"] = f["sev"]
        if f["rule_id"] not in m["rids"]: m["rids"].append(f["rule_id"])
    prices, cal = _jload("prices.json"), _jload("calibration.json")
    fix_t, fix_kind = fix_estimate(lines, lib, cost.get("file_chars", {}), cost.get("text_chars", 0), cal.get("fix", 1.0))
    fix_size = size_label(fix_t) if fix_t else "None"
    audit_usd, fix_usd = usd(audit_t, "opus", 0.9, prices), usd(fix_t, "sonnet", 0.6, prices)

    out = []
    if not live:
        head = "⚪ Safe to install · No problems found"
    else:
        head = f"{ICON[worst]} {HEAD[worst]}"
        if worst == "CRITICAL": head += " · No fix offered: rebuild from purpose instead"
        elif worst in ("HIGH", "MEDIUM"): head += f" · Fix cost: {fix_size}"
    out.append(("## " if md else "") + head)
    tgt = os.path.basename(str(scan.get("target", "")).rstrip("/")) or "target"
    state = "Reviewed" if review is not None else "Scanner result, not yet reviewed"
    out.append(cost_bar(audit_t, fix_t, fix_kind) + "  " + legend(audit_t, audit_usd, fix_t, fix_kind, fix_usd, prices))
    out.append(f"{tgt} · {len(scan.get('files', []))} files · {state}")
    out.append("")
    if live:
        if md:
            out += ["| Level | Found | What you do |", "|---|---|---|"]
            out += [f"| {ICON[s]} {NAME[s]} | {counts[s]} | {ACTION[s]} |" for s in sorted(ORDER, key=lambda s: -ORDER[s]) if counts[s]]
        else:
            out += [f"{ICON[s]} {NAME[s]} x{counts[s]}: {ACTION[s]}" for s in sorted(ORDER, key=lambda s: -ORDER[s]) if counts[s]]
        out.append("")
        # group by rule id ("same_as" in the library merges near-duplicate rules into one bullet)
        rules = {}
        for f in live:
            rules.setdefault(lib.get(f["rule_id"], {}).get("same_as", f["rule_id"]), []).append(f)
        known, unusual = {}, []
        for rid, fs in rules.items():
            e = lib.get(rid)
            w = max((f["sev"] for f in fs), key=lambda s: ORDER[s])
            if e: known.setdefault(e["category"], []).append((rid, e, fs, w))
            else: unusual.append((rid, fs, w))
        out.append("### Problems" if md else "PROBLEMS")
        cats = sorted(known, key=lambda c: (-max(ORDER[x[3]] for x in known[c]), CAT_POS.get(c, 99)))
        for c in cats:
            cw = max((x[3] for x in known[c]), key=lambda s: ORDER[s])
            out.append(f"{b(CAT_ICON.get(c, '') + ' ' + c)} {ICON[cw]}")
            for rid, e, fs, w in sorted(known[c], key=lambda x: (-ORDER[x[3]], x[0])):
                out.append(f"- {ICON[w]} {b(e['what'])} ({fmt_locs(locs(fs, lambda f: f['loc']))}){' (suspected)' if all(f['confidence'] == 'suspected' for f in fs) else ''}")
                out.append(f"  Like: {e['like']} · Fix: {e['fix']} · Fix cost: {e['fix_tier']}")
        if unusual:
            out.append(b("Unusual (Claude explains below):") + " " + "; ".join(
                f"{ICON[w]} {rid} ({fmt_locs(locs(fs, lambda f: f['loc']))})" for rid, fs, w in sorted(unusual, key=lambda x: -ORDER[x[2]])))
        big = [(n, t, s, d) for n, t, s, d in (("Auditing", audit_t, cost.get("audit_size", ""), audit_usd), ("Fixing", fix_t, fix_size, fix_usd)) if s in ("Large", "Very Large")]
        for n, t, s, d in big:
            out.append(b("💸 Cost") + f" — {n} this is {s} (~{t // 1000}k tokens{', ' + fmt_usd(d) if d is not None else ''}). Ask before continuing.")
    if checked:
        shown = "; ".join(f"`{l}` {r}" for l, r in checked[:5])
        out.append(f"⚪ Checked, not a problem: {len(checked)} ({shown}" + (f"; +{len(checked) - 5} more" if len(checked) > 5 else "") + ")")
    text = "\n".join(out)
    if not md: text = text.replace("`", "")
    print(text)


if __name__ == "__main__":
    main()
