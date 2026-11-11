#!/usr/bin/env python3
"""Fix mode (CARD-SPEC §12). The original is never modified.
Usage (run as: python3 -I -B fix.py ...):
  plan   <src> [--review r.json] [--include-low] [--json]   route + mechanical list + judgment list + cost
  apply  <src> --out <dir> [--review r.json] [--include-low] [--source URL] [--sha SHA]
         copy to <dir> (default <src-parent>/<name>-safe), run mechanical fixes, write provenance.json, re-scan.
         exit 3 on the rebuild route, 4 when nothing to fix, 2 on bad input.
  record <safe> --file F --line N --rule R --note "..." [--end-line M] [--kind judgment|condition]
         log one judgment edit (N = line number in the ORIGINAL file, as in the scan).
  verify <src> <safe> [--review r.json] [--include-low]    unlisted changes + re-scan; exit 0 only if proof 1 and 2 pass.
<src> may be a bundle target of encoded test samples: bundle:<bundle.json>#<set>[/<subdir-or-file>] (decoded in memory,
  scanned via scan.py --bundle; plan/verify work, apply on a patch route refuses (exit 2): attack text is never written out).
Stdlib only, no network. Scans via scan.py --json (subprocess); never executes the target. Never writes into ~/.claude.
"""
import argparse, base64, datetime, difflib, hashlib, json, math, os, re, shutil, stat, subprocess, sys, zlib

HERE = os.path.dirname(os.path.abspath(__file__))
BASE = os.path.join(HERE, "..")
SCAN = os.path.join(HERE, "scan.py")
ORDER = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "INFO": 0}
MALICIOUS = {"injection.hides-actions-from-the-user", "injection.instruction-override-attempt",
             "injection.role-system-hijack-phrasing", "secrets.secret-sent-over-network"}
INVISIBLE = {"​", "‌", "‍", "⁠", "﻿", "­"}
BIDI = {chr(c) for c in list(range(0x202A, 0x202F)) + list(range(0x2066, 0x206A))}
MD_EXT = {".md", ".mdx", ".txt"}
SCRIPT_EXT = {".sh", ".py", ".js", ".mjs", ".cjs", ".ts", ".rb"}
BIN_EXT = {".exe", ".dll", ".so", ".dylib", ".bin", ".pyc", ".pyo", ".class", ".jar", ".app", ".pkg", ".dmg", ".msi",
           ".deb", ".rpm", ".node", ".wasm", ".zip", ".tar", ".gz", ".tgz", ".7z", ".rar", ".xz", ".bz2",
           ".png", ".jpg", ".jpeg", ".gif", ".ico", ".pdf", ".woff", ".woff2", ".ttf", ".otf"}
UPDATE_RE = re.compile(r"^(auto[-_]?update|self[-_]?update|update[-_]?(self|skill|plugin)s?)\b.*\.(sh|py|js|mjs|ts|rb)$", re.I)
NPX_Y = re.compile(r"(?<=\bnpx)\s+(?:-y|--yes)(?=\s)", re.I)
SKILLS_Y = re.compile(r"\s+(?:-y|--yes)(?=\s|$|[`\"')\]])", re.I)
SKILLS_LINE = re.compile(r"\bskills\s+(?:add|install)\b", re.I)
AD_RIDS = ("ads.advertising-affiliate-content", "ads.self-promotion-instruction")
UPSTREAM = "review the diff vs {sha} before taking any update"
# --- Cost model (CARD-SPEC §9), duplicated from card.py on purpose.
SIZES = [(5_000, "Very Small"), (20_000, "Small"), (60_000, "Medium"), (150_000, "Large"), (float("inf"), "Very Large")]
TIER_TOK = {"Script (free)": 0, "Very Small": 200, "Small": 500}
TIER_RANK = {"Script (free)": 0, "Very Small": 1, "Small": 2, "Rewrite": 3}
FIX_OVERHEAD = 1000


def die(msg, code=2):
    sys.stderr.write(f"fix.py: {msg}\n")
    sys.exit(code)


def jload(name):
    try:
        with open(os.path.join(BASE, name), encoding="utf-8") as fh:
            return json.load(fh)
    except (OSError, ValueError):
        return {}


def size_label(t):
    return next(l for lim, l in SIZES if t < lim)


def fix_estimate(lines, lib, file_chars, text_chars, factor=1.0):
    if any(m["sev"] == "CRITICAL" for m in lines.values()):
        return round((2 * (text_chars // 4) + FIX_OVERHEAD) * factor), "rebuild"
    tier_of = {}
    for (fp, ln), m in lines.items():
        if m["sev"] in ("LOW", "INFO"):
            continue
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


# ---------------------------------------------------------------- scan + review
_BUNDLES = {}


def parse_bundle(spec):
    """'bundle:<path>#<set>[/<sub>]' -> (path, set, sub) or None."""
    if not spec.startswith("bundle:") or "#" not in spec:
        return None
    path, _, rest = spec[7:].rpartition("#")
    name, _, sub = rest.partition("/")
    return path, name, sub.strip("/")


def bundle_files(spec):
    """{relpath: bytes} of the selected set/subtree, decoded in memory (rel paths are relative to the subtree)."""
    b = parse_bundle(spec)
    if spec not in _BUNDLES:
        try:
            with open(b[0], encoding="utf-8") as fh:
                blob = json.load(fh)["sets"][b[1]]
            allf = json.loads(zlib.decompress(base64.b64decode(blob)).decode("utf-8"))
        except (OSError, ValueError, KeyError, zlib.error) as e:
            die(f"cannot read bundle target {spec}: {e}")
        out = {}
        for rel, t in allf.items():
            if not b[2]:
                out[rel] = t.encode("utf-8")
            elif rel == b[2]:
                out[os.path.basename(rel)] = t.encode("utf-8")
            elif rel.startswith(b[2] + "/"):
                out[rel[len(b[2]) + 1:]] = t.encode("utf-8")
        if not out:
            die(f"bundle target {spec} selects no files")
        _BUNDLES[spec] = out
    return _BUNDLES[spec]


def run_scan(path, exclude=None):
    if parse_bundle(path):
        files = bundle_files(path)
        enc = base64.b64encode(zlib.compress(json.dumps({r: t.decode("utf-8") for r, t in files.items()}).encode("utf-8"))).decode("ascii")
        cmd = [sys.executable, "-I", "-B", SCAN, "-", "--bundle", "--set=x", "--json"] + ([f"--exclude={exclude}"] if exclude else [])
        p = subprocess.run(cmd, input=json.dumps({"sets": {"x": enc}}), capture_output=True, text=True, encoding="utf-8")
        try:
            return json.loads(p.stdout), p.returncode
        except ValueError:
            die(f"scan.py gave no JSON for {path}: {p.stderr.strip()[:200]}")
    cmd = [sys.executable, "-I", "-B", SCAN, path, "--json"] + ([f"--exclude={exclude}"] if exclude else [])
    p = subprocess.run(cmd, capture_output=True, text=True, encoding="utf-8")
    try:
        return json.loads(p.stdout), p.returncode
    except ValueError:
        die(f"scan.py gave no JSON for {path}: {p.stderr.strip()[:200]}")


def load_review(path):
    if not path:
        return None
    try:
        with open(path, encoding="utf-8") as fh:
            r = json.load(fh)
        if not isinstance(r, dict):
            raise ValueError("not an object")
        return r
    except (OSError, ValueError) as e:
        die(f"cannot read review {path}: {e}")


def canon(lib, rid):
    return lib.get(rid, {}).get("same_as", rid)


def live_findings(scan, review):
    """Same review semantics as card.py: dismiss / level (by file:line)."""
    dismiss = (review or {}).get("dismiss", {})
    relevel = (review or {}).get("level", {})
    out = []
    for f in scan["findings"]:
        loc = f"{f['file']}:{f['line']}"
        if loc in dismiss:
            continue
        sev = relevel.get(loc, f["severity"])
        if sev not in ORDER:
            sev = f["severity"]
        out.append(dict(f, sev=sev, loc=loc))
    return out


def decide(act, lib):
    if not act:
        return "none", ["no MEDIUM+ finding left after review (use --include-low to fix LOW too)"]
    why = []
    for f in act:
        rid = canon(lib, f["rule_id"])
        if f["sev"] == "CRITICAL":
            why.append(f"CRITICAL {rid} at {f['loc']}")
        elif lib.get(rid, {}).get("fix_tier") == "Rewrite":
            why.append(f"Rewrite-tier {rid} at {f['loc']}")
        elif f["sev"] == "HIGH" and rid in MALICIOUS:
            why.append(f"HIGH {rid} at {f['loc']} (malicious intent)")
    return ("rebuild", why) if why else ("patch", [])


# ---------------------------------------------------------------- text helpers
class Text:
    def __init__(self, path, data=None):
        if data is not None:
            self.text = data.decode("utf-8", errors="surrogateescape")
        else:
            with open(path, "r", encoding="utf-8", errors="surrogateescape", newline="") as fh:
                self.text = fh.read()
        self.lines = self.text.splitlines(True)
        self.offs, o = [], 0
        for l in self.lines:
            self.offs.append(o)
            o += len(l)

    def body(self, i):
        return self.lines[i].rstrip("\r\n")

    def line_of(self, off):
        lo, hi = 0, len(self.offs) - 1
        while lo < hi:
            mid = (lo + hi + 1) // 2
            if self.offs[mid] <= off:
                lo = mid
            else:
                hi = mid - 1
        return lo + 1


def is_bad(c):
    return c in INVISIBLE or c in BIDI or 0xE0000 <= ord(c) <= 0xE007F


def read_text(path):
    return Text(path)


def is_text_file(full):
    if os.path.islink(full) or os.path.splitext(full)[1].lower() in BIN_EXT:
        return False
    try:
        with open(full, "rb") as fh:
            return b"\x00" not in fh.read(8000)
    except OSError:
        return False


def line_states(t, is_skill_md, is_md):
    fm, fence = [False] * len(t.lines), [False] * len(t.lines)
    in_fm = in_fence = False
    for i, l in enumerate(t.lines):
        s = l.lstrip("﻿").strip() if i == 0 else l.strip()
        if is_skill_md and i == 0 and s == "---":
            in_fm = True
        fm[i], fence[i] = in_fm, in_fence
        if is_md and s.startswith(("```", "~~~")):
            in_fence = not in_fence
        if in_fm and i > 0 and s == "---":
            in_fm = False
    return fm, fence


def whole_line_ad(body):
    s = body.strip()
    if not s or len(s) > 160 or "`" in s or "|" in s or s.startswith(("#", "<", "---")):
        return False
    return len([p for p in re.split(r"(?<=[.!?])\s+", s) if p]) <= 2


def show_bad(line):
    return "".join(f"<U+{ord(c):04X}>" if is_bad(c) else c for c in line)


def frontmatter_rest(lines):
    """Frontmatter lines minus the name: line, invisibles removed (for the description check)."""
    if not lines or lines[0].lstrip("﻿").strip() != "---":
        return None
    out = []
    for l in lines[1:]:
        if l.strip() == "---":
            return [x for x in out]
        if not re.match(r"\s*name\s*:", l):
            out.append("".join(c for c in l.rstrip("\r\n") if not is_bad(c)).strip())
    return out


# ---------------------------------------------------------------- plan
def build_plan(src, review, include_low):
    if parse_bundle(src):
        bundle_files(src)
    elif not os.path.exists(src):
        die(f"no such path: {src}")
    scan, _ = run_scan(src)
    lib = jload("explanations.json")
    live = live_findings(scan, review)
    thr = 1 if include_low else 2
    act = [f for f in live if ORDER[f["sev"]] >= thr]
    route, why = decide(act, lib)
    P = {"src": src, "scan": scan, "lib": lib, "live": live, "act": act, "route": route, "why": why,
         "mech": [], "judgment": [], "covered": set(), "texts": {}}
    if route == "patch":
        plan_mech(P)
    seen = {}
    for f in act:
        if id(f) in P["covered"]:
            continue
        g = seen.setdefault((f["file"], f["line"]), {"file": f["file"], "line": f["line"], "sev": f["sev"], "rules": [], "fix": ""})
        rid = canon(lib, f["rule_id"])
        if rid not in g["rules"]:
            g["rules"].append(rid)
        if ORDER[f["sev"]] > ORDER[g["sev"]]:
            g["sev"] = f["sev"]
        if not g["fix"]:
            g["fix"] = lib.get(rid, {}).get("fix") or next((c["fix"] for c in scan.get("cheapest_rewrite", []) if c["category"] == f["category"]), "")
    P["judgment"] = sorted(seen.values(), key=lambda g: (-ORDER[g["sev"]], g["file"], g["line"]))
    P["cost"] = cost_of(P)
    return P


def cost_of(P):
    scan, lib = P["scan"], P["lib"]
    cost, cal, prices = scan.get("cost", {}), jload("calibration.json"), jload("prices.json")
    if P["route"] == "none":
        t, kind = 0, "none"
    elif P["route"] == "rebuild":
        t, kind = round((2 * (cost.get("text_chars", 0) // 4) + FIX_OVERHEAD) * cal.get("fix", 1.0)), "rebuild"
    else:
        lines = {}
        for f in P["live"]:
            m = lines.setdefault((f["file"], f["line"]), {"sev": f["sev"], "rids": []})
            if ORDER[f["sev"]] > ORDER[m["sev"]]:
                m["sev"] = f["sev"]
            if f["rule_id"] not in m["rids"]:
                m["rids"].append(f["rule_id"])
        t, kind = fix_estimate(lines, lib, cost.get("file_chars", {}), cost.get("text_chars", 0), cal.get("fix", 1.0))
    d = usd(t, "sonnet", 0.6, prices)
    return {"tokens": t, "size": size_label(t) if t else "None", "kind": kind, "usd": d}


def plan_mech(P):
    src, act, lib, scan = P["src"], P["act"], P["lib"], P["scan"]
    mech, edits = P["mech"], {}
    if not os.path.isdir(src):
        return
    root_real = os.path.realpath(src)

    def text(rel):
        if rel not in P["texts"]:
            P["texts"][rel] = read_text(os.path.join(src, rel))
        return P["texts"][rel]

    def textual(rel):
        return is_text_file(os.path.join(src, rel))

    def cover(rel, lo, hi=None, only=None):
        for f in P["live"]:
            if f["file"] == rel and lo <= f["line"] <= (hi or lo) and (only is None or canon(lib, f["rule_id"]) in only):
                P["covered"].add(id(f))

    def add(rel, line, rid, kind, before, after, note, ed=(), end=None, **extra):
        fx = {"file": rel, "line": line, "rule_id": rid, "kind": kind, "before": before, "after": after, "note": note}
        if end and end != line:
            fx["end_line"] = end
        fx.update(extra)
        fx["_edits"] = list(ed)
        mech.append(fx)
        if ed:
            edits.setdefault(rel, []).extend(ed)

    skill_md = os.path.join(src, "SKILL.md")
    # 1. HTML comments (Markdown/text): delete the whole comment, keep the text in the report
    spans = {}  # rel -> [(first_line, last_line)]
    cm_lines = {}
    for f in act:
        if canon(lib, f["rule_id"]) in ("injection.html-comment", "injection.hidden-html-comment") and f["line"] > 0 \
                and os.path.splitext(f["file"])[1].lower() in MD_EXT and textual(f["file"]):
            cm_lines.setdefault(f["file"], set()).add(f["line"])
    for rel, lns in cm_lines.items():
        t = text(rel)
        for m in re.finditer(r"<!--([\s\S]*?)-->", t.text):
            l1 = t.line_of(m.start())
            if l1 not in lns:
                continue
            s, e = m.start(), m.end()
            ls = t.offs[l1 - 1]
            l2 = t.line_of(max(e - 1, 0))
            le = t.offs[l2 - 1] + len(t.lines[l2 - 1])
            if not t.text[ls:s].strip() and not t.text[e:le].strip():
                s, e = ls, le  # comment alone on its line(s): drop the lines
            add(rel, l1, "injection.html-comment", "mechanical", m.group(0)[:500], "", "hidden HTML comment deleted; removed text kept in 'before'",
                [(s, e, "")], end=l2)
            spans.setdefault(rel, []).append((l1, l2))
            cover(rel, l1, l2)

    def in_span(rel, ln):
        return any(a <= ln <= b for a, b in spans.get(rel, []))

    # 2. invisible / bidi / tag characters
    done = set()
    for f in act:
        if canon(lib, f["rule_id"]) == "injection.invisible-bidi-tag-unicode" and f["line"] > 0 and textual(f["file"]) \
                and (f["file"], f["line"]) not in done and not in_span(f["file"], f["line"]):
            done.add((f["file"], f["line"]))
            t = text(f["file"])
            if f["line"] > len(t.lines):
                continue
            ls = t.offs[f["line"] - 1]
            line = t.body(f["line"] - 1)
            ed = [(ls + i, ls + i + 1, "") for i, c in enumerate(line) if is_bad(c) and not (ls + i == 0 and c == "﻿")]
            if ed:
                add(f["file"], f["line"], "injection.invisible-bidi-tag-unicode", "mechanical", show_bad(line),
                    "".join(c for i, c in enumerate(line) if not (is_bad(c) and not (ls + i == 0 and c == "﻿"))),
                    "invisible/bidi/tag characters deleted (BOM at file start kept)", ed)
                cover(f["file"], f["line"], only={"injection.invisible-bidi-tag-unicode"})
    # 3. ad lines that are entirely an ad
    for f in act:
        rel, ln = f["file"], f["line"]
        if canon(lib, f["rule_id"]) not in AD_RIDS or ln <= 0 or id(f) in P["covered"] or in_span(rel, ln) \
                or os.path.splitext(rel)[1].lower() not in MD_EXT or not textual(rel):
            continue
        t = text(rel)
        if ln > len(t.lines):
            continue
        fm, fence = line_states(t, os.path.basename(rel) == "SKILL.md", os.path.splitext(rel)[1].lower() in (".md", ".mdx"))
        if fm[ln - 1] or fence[ln - 1] or not whole_line_ad(t.body(ln - 1)):
            continue
        if any(m["file"] == rel and m["line"] == ln and m["rule_id"] == "ads.advertising-affiliate-content" for m in mech):
            cover(rel, ln)
            continue
        add(rel, ln, "ads.advertising-affiliate-content", "mechanical", t.body(ln - 1), "", "advertising line deleted",
            [(t.offs[ln - 1], t.offs[ln - 1] + len(t.lines[ln - 1]), "")])
        cover(rel, ln)
    # 4. auto-confirm flags (any text file line, findings not required)
    for rel in scan.get("files", []):
        if not textual(rel):
            continue
        t = text(rel)
        for i, l in enumerate(t.lines):
            ln = i + 1
            if in_span(rel, ln) or any(m["file"] == rel and m["line"] == ln and m["after"] == "" and m["kind"] == "mechanical" and "line deleted" in m["note"] for m in mech):
                continue
            body = t.body(i)
            hits = [(m.start(), m.end()) for m in NPX_Y.finditer(body)]
            if SKILLS_LINE.search(body):
                hits += [(m.start(), m.end()) for m in SKILLS_Y.finditer(body)]
            hits = sorted(set(hits))
            if hits:
                new = body
                for a, b in reversed(hits):
                    new = new[:a] + new[b:]
                add(rel, ln, "fix.auto-confirm-flag", "mechanical", body, new, "removed -y/--yes auto-confirm flag",
                    [(t.offs[i] + a, t.offs[i] + b, "") for a, b in hits])
    # 5. exec bit on non-scripts, 6. symlinks pointing outside
    for f in P["live"]:
        rel = f["file"]
        full = os.path.join(src, rel)
        rid = canon(lib, f["rule_id"])
        if rid == "filesystem.file-is-executable" and not os.path.islink(full) and os.path.isfile(full):
            if os.path.splitext(rel)[1].lower() in SCRIPT_EXT:
                continue
            with open(full, "rb") as fh:
                if fh.read(2) == b"#!":
                    continue
            mode = stat.S_IMODE(os.lstat(full).st_mode)
            add(rel, 0, rid, "mechanical", f"mode {mode:o}", f"mode {mode & ~0o111:o}", "exec bit cleared (not a script)", _chmod=mode & ~0o111)
            P["covered"].add(id(f))
        elif rid == "filesystem.symlink" and os.path.islink(full) and not os.path.realpath(full).startswith(root_real + os.sep):
            add(rel, 0, rid, "removed-file", "symlink -> " + os.readlink(full), "", "symlink pointing outside the skill deleted", _delete=True)
            P["covered"].add(id(f))
    # 7. update scripts (auto-update off)
    for rel in scan.get("files", []):
        if UPDATE_RE.match(os.path.basename(rel)) and not any(m["file"] == rel and m["kind"] == "removed-file" for m in mech):
            add(rel, 0, "fix.update-script", "removed-file", rel, "", "update script removed (auto-update off)", _delete=True)
            cover(rel, 0, 10 ** 9)
    # 8. frontmatter name -> <name>-safe
    if os.path.isfile(skill_md) and not os.path.islink(skill_md):
        t = text("SKILL.md")
        fm, _ = line_states(t, True, True)
        for i in range(len(t.lines)):
            if not fm[i]:
                continue
            m = re.match(r"^(\s*name\s*:\s*)([\"']?)([^\"'\r\n#]+?)\2\s*$", t.body(i))
            if m:
                if not m.group(3).endswith("-safe") and not in_span("SKILL.md", i + 1):
                    a = t.offs[i] + m.start(3)
                    b = t.offs[i] + m.end(3)
                    add("SKILL.md", i + 1, "fix.rename-safe", "mechanical", m.group(3), m.group(3) + "-safe",
                        "frontmatter name gets -safe so it can sit beside the original", [(a, b, m.group(3) + "-safe")])
                break
    P["edits"] = edits


# ---------------------------------------------------------------- tree helpers
def tree_hashes(root):
    out = {}
    for d, dirs, files in os.walk(root):
        dirs[:] = [x for x in dirs if x != ".git"]
        for n in files + [x for x in dirs if os.path.islink(os.path.join(d, x))]:
            p = os.path.join(d, n)
            rel = os.path.relpath(p, root)
            if os.path.islink(p):
                out[rel] = "symlink:" + os.readlink(p)
            else:
                with open(p, "rb") as fh:
                    out[rel] = hashlib.sha256(fh.read()).hexdigest()
    return out


def tree_modes(root):
    return {os.path.relpath(os.path.join(d, n), root): stat.S_IMODE(os.lstat(os.path.join(d, n)).st_mode)
            for d, dirs, files in os.walk(root) for n in files if not os.path.islink(os.path.join(d, n))}


def src_hashes(src):
    """tree_hashes for a directory or an in-memory bundle target."""
    if parse_bundle(src):
        return {r: hashlib.sha256(b).hexdigest() for r, b in bundle_files(src).items()}
    return tree_hashes(src)


def is_mem_text(rel, data):
    return os.path.splitext(rel)[1].lower() not in BIN_EXT and b"\x00" not in data[:8000]


def skill_name(src):
    try:
        t = read_text(os.path.join(src, "SKILL.md"))
        for l in t.lines[1:]:
            if l.strip() == "---":
                break
            m = re.match(r"\s*name\s*:\s*[\"']?([^\"'\r\n#]+?)[\"']?\s*$", l)
            if m:
                return m.group(1)
    except OSError:
        pass
    return os.path.basename(os.path.abspath(src).rstrip("/"))


def public(fx):
    return {k: v for k, v in fx.items() if not k.startswith("_")}


# ---------------------------------------------------------------- commands
def cmd_plan(a):
    P = build_plan(a.src, load_review(a.review), a.include_low)
    c = P["cost"]
    if a.json:
        print(json.dumps({"route": P["route"], "why": P["why"], "mechanical": [public(m) for m in P["mech"]],
                          "judgment": P["judgment"], "cost": c}, indent=1))
        return 0
    print(f"Route: {P['route']}" + (f" ({'; '.join(P['why'][:4])}{'; ...' if len(P['why']) > 4 else ''})" if P["why"] else ""))
    if P["route"] == "none":
        print(P["why"][0])
    elif P["route"] == "rebuild":
        print("No patch. Claude writes a fresh skill from the stated purpose (frontmatter description + README, not its code) into <name>-safe/; copy no file from the original.")
    else:
        print(f"Mechanical (script, 0 LLM tokens): {len(P['mech'])}")
        for m in P["mech"]:
            print(f"  - {m['file']}:{m['line']} {m['rule_id']}: {m['note']}")
        print(f"Judgment (Claude, smallest edit each, then `fix.py record`): {len(P['judgment'])}")
        for g in P["judgment"]:
            print(f"  - {g['file']}:{g['line']} [{g['sev']}] {', '.join(g['rules'])}: {g['fix']}")
    if c["tokens"]:
        label = "Rebuild" if c["kind"] == "rebuild" else "Fix"
        print(f"Cost: {label} ~{round(c['tokens'] / 1000) or '<1'}k tokens {c['size']} {fmt_usd(c['usd'])} (Sonnet)".rstrip())
    return 0


def under_claude(path):
    real = os.path.realpath(path)
    cl = os.path.realpath(os.path.expanduser("~/.claude"))
    return real == cl or real.startswith(cl + os.sep)


def cmd_apply(a):
    bun = parse_bundle(a.src)
    src = a.src if bun else os.path.abspath(a.src)
    P = build_plan(src, load_review(a.review), a.include_low)
    if P["route"] == "rebuild":
        print("Route: rebuild. No patch is offered (" + "; ".join(P["why"][:3]) + "). Write a fresh skill from the stated purpose.")
        return 3
    if P["route"] == "none":
        print("Route: none. " + P["why"][0])
        return 4
    if bun:
        die("bundle targets are test samples; patch a real folder")
    if not os.path.isdir(src):
        die("apply needs a skill directory")
    out = os.path.abspath(a.out) if a.out else os.path.join(os.path.dirname(src.rstrip("/")), skill_name(src) + "-safe")
    if under_claude(out):
        die(f"refusing to write into ~/.claude: {out} (install is a separate, user-approved step)")
    if out == src or out.startswith(src + os.sep) or src.startswith(out + os.sep):
        die("--out must not overlap the source")
    if os.path.exists(out) and os.listdir(out):
        die(f"--out exists and is not empty: {out}")
    before = tree_hashes(src)
    shutil.copytree(src, out, symlinks=True, ignore=shutil.ignore_patterns(".git"))
    for rel, eds in P["edits"].items():
        t = P["texts"][rel]
        keep, last = [], -1
        for s, e, r in sorted(eds, key=lambda x: (x[0], x[1])):
            if s >= last:  # drop an edit already inside an earlier span
                keep.append((s, e, r))
                last = max(e, s)
        txt = t.text
        for s, e, r in reversed(keep):
            txt = txt[:s] + r + txt[e:]
        with open(os.path.join(out, rel), "w", encoding="utf-8", errors="surrogateescape", newline="") as fh:
            fh.write(txt)
    for m in P["mech"]:
        p = os.path.join(out, m["file"])
        if m.get("_delete") and os.path.lexists(p):
            os.remove(p)
        if "_chmod" in m:
            os.chmod(p, m["_chmod"])
    if tree_hashes(src) != before:
        die("source changed during apply (should be impossible)", 5)
    rescan, code = run_scan(out, "provenance.json")
    prov = {"source": a.source or src, "sha": a.sha or "tree-sha256:" + hashlib.sha256(json.dumps(before, sort_keys=True).encode()).hexdigest()[:12],
            "route": "patch", "created": datetime.datetime.now().isoformat(timespec="seconds"), "src_path": src,
            "original_hashes": before, "fixes": [public(m) for m in P["mech"]],
            "rescan": {"counts": rescan.get("counts", {}), "exit": code}, "auto_update": False}
    prov["upstream"] = UPSTREAM.format(sha=prov["sha"])
    with open(os.path.join(out, "provenance.json"), "w", encoding="utf-8") as fh:
        json.dump(prov, fh, indent=2)
    c = rescan.get("counts", {})
    print(f"Route: patch · wrote {out}")
    print(f"Mechanical fixes applied: {len(P['mech'])}")
    for m in P["mech"]:
        print(f"  - {m['file']}:{m['line']} {m['rule_id']}: {m['note']}")
        if m["rule_id"] == "injection.html-comment":
            print(f"      removed text: {m['before'][:200]}")
    print(f"Judgment edits left for Claude: {len(P['judgment'])}")
    for g in P["judgment"]:
        print(f"  - {g['file']}:{g['line']} [{g['sev']}] {', '.join(g['rules'])}: {g['fix']}")
    print(f"Re-scan: C={c.get('CRITICAL', 0)} H={c.get('HIGH', 0)} M={c.get('MEDIUM', 0)} L={c.get('LOW', 0)} (exit {code})")
    print("Original untouched. After judgment edits: fix.py record <safe> ..., then fix.py verify <src> <safe>.")
    return 0


def diff_blocks(a_lines, b_lines):
    return [o for o in difflib.SequenceMatcher(None, a_lines, b_lines, autojunk=False).get_opcodes() if o[0] != "equal"]


def cmd_record(a):
    safe = os.path.abspath(a.safe)
    pp = os.path.join(safe, "provenance.json")
    try:
        with open(pp, encoding="utf-8") as fh:
            prov = json.load(fh)
    except (OSError, ValueError):
        die(f"no readable provenance.json in {safe}")
    before = after = ""
    kind = a.kind
    if kind == "judgment":
        sp, op = os.path.join(safe, a.file), os.path.join(prov.get("src_path", ""), a.file)
        if not os.path.lexists(sp):
            kind = "removed-file"
        elif os.path.isfile(op) and os.path.isfile(sp) and is_text_file(op) and is_text_file(sp):
            o, s = read_text(op).lines, read_text(sp).lines
            hit = [b for b in diff_blocks(o, s) if (b[1] if b[1] == b[2] else b[1] + 1) <= a.line <= max(b[2], b[1] + 1)]
            if hit:
                b = hit[0]
                before, after = "".join(o[b[1]:b[2]]).rstrip("\r\n")[:500], "".join(s[b[3]:b[4]]).rstrip("\r\n")[:500]
            else:
                sys.stderr.write(f"fix.py: warning: no change found at {a.file}:{a.line} in the safe copy\n")
    fx = {"file": a.file, "line": a.line, "rule_id": a.rule, "kind": kind, "before": before, "after": after, "note": a.note}
    if a.end_line and a.end_line != a.line:
        fx["end_line"] = a.end_line
    prov["fixes"].append(fx)
    with open(pp, "w", encoding="utf-8") as fh:
        json.dump(prov, fh, indent=2)
    print(f"Recorded {kind}: {a.file}:{a.line} {a.rule}")
    return 0


def covered_by(fixes, rel, lo, hi):
    return any(f["file"] == rel and f["line"] <= hi and f.get("end_line", f["line"]) >= lo for f in fixes)


def unlisted_changes(src, safe, fixes):
    out = []
    mem = bundle_files(src) if parse_bundle(src) else None
    oh, sh = src_hashes(src), tree_hashes(safe)
    sh.pop("provenance.json", None)
    om, sm = ({} if mem is not None else tree_modes(src)), tree_modes(safe)
    for rel in sorted(oh):
        mine = [f for f in fixes if f["file"] == rel]
        if rel not in sh:
            if not any(f["kind"] == "removed-file" or f["line"] == 0 for f in mine):
                out.append(f"{rel}: file removed (no 'removed-file' fix listed)")
            continue
        if oh[rel] == sh[rel]:
            if rel in om and om.get(rel) != sm.get(rel) and (om.get(rel, 0) ^ sm.get(rel, 0)) & 0o111 and not mine:
                out.append(f"{rel}: exec bit changed (not listed)")
            continue
        fo, fs = os.path.join(src, rel), os.path.join(safe, rel)
        if not ((is_mem_text(rel, mem[rel]) if mem is not None else is_text_file(fo)) and is_text_file(fs)):
            if not mine:
                out.append(f"{rel}: content changed (binary or link, not listed)")
            continue
        o, s = (Text(None, mem[rel]) if mem is not None else read_text(fo)).lines, read_text(fs).lines
        for tag, i1, i2, j1, j2 in diff_blocks(o, s):
            span = [(i1, i1 + 1)] if i1 == i2 else [(L, L) for L in range(i1 + 1, i2 + 1)]
            for lo, hi in span:
                ok = covered_by(fixes, rel, lo, hi)
                if not ok and lo == hi:  # run of identical lines: difflib may pick another copy of the same text
                    k = lo
                    for step in (-1, 1):
                        x = lo - 1 + step
                        while not ok and 0 <= x < len(o) and o[x] == o[lo - 1]:
                            ok = covered_by(fixes, rel, x + 1, x + 1)
                            x += step
                if not ok:
                    txt = ("".join(o[i1:i2]) or "".join(s[j1:j2])).strip()[:80]
                    out.append(f"{rel}:{lo if lo == hi else i1}: unlisted change ({tag}) {txt!r}")
                    break
        if om.get(rel) is not None and sm.get(rel) is not None and (om[rel] ^ sm[rel]) & 0o111 and not mine:
            out.append(f"{rel}: exec bit changed (not listed)")
    for rel in sorted(set(sh) - set(oh)):
        if not any(f["file"] == rel for f in fixes):
            out.append(f"{rel}: file added (not listed)")
    return out


def cmd_verify(a):
    src, safe = (a.src if parse_bundle(a.src) else os.path.abspath(a.src)), os.path.abspath(a.safe)
    mem = bundle_files(src) if parse_bundle(src) else None
    review = load_review(a.review)
    P = build_plan(src, review, a.include_low)
    rescan, code = run_scan(safe, "provenance.json")
    # a dismissed original finding is not counted again if the same (file, rule, snippet) is still present
    skip = set()
    dismiss = (review or {}).get("dismiss", {})
    for f in P["scan"]["findings"]:
        if f"{f['file']}:{f['line']}" in dismiss:
            skip.add((f["file"], f["rule_id"], f["snippet"]))
    left = [f for f in rescan["findings"] if f["severity"] in ("CRITICAL", "HIGH") and (f["file"], f["rule_id"], f["snippet"]) not in skip]
    # findings that only exist in the safe copy (introduced by a fix, e.g. a new --exclude='.ssh') can be
    # dismissed explicitly by safe-copy file:line with a reason; they are always printed, never hidden
    dsafe = (review or {}).get("dismiss_safe", {})
    for f in [f for f in left if f"{f['file']}:{f['line']}" in dsafe]:
        print(f"  dismissed in safe copy: {f['severity']} {f['file']}:{f['line']} {f['rule_id']} ({dsafe[f['file'] + ':' + str(f['line'])]})")
    left = [f for f in left if f"{f['file']}:{f['line']}" not in dsafe]
    c = rescan.get("counts", {})
    p1 = not left
    problems = []
    fixes = []
    if P["route"] == "rebuild":
        oh = {h: r for r, h in src_hashes(src).items() if not h.startswith("symlink:")}
        for rel, h in tree_hashes(safe).items():
            if h in oh and os.path.getsize(os.path.join(safe, rel)) > 0 and rel != "provenance.json":
                problems.append(f"{rel}: identical to original {oh[h]} (rebuild must not copy files)")
        mode = "rebuild"
    else:
        mode = "patch"
        try:
            with open(os.path.join(safe, "provenance.json"), encoding="utf-8") as fh:
                fixes = json.load(fh)["fixes"]
        except (OSError, ValueError, KeyError):
            die(f"no readable provenance.json in {safe} (run fix.py apply first)")
        problems = unlisted_changes(src, safe, fixes)
        so, ss = os.path.join(src, "SKILL.md"), os.path.join(safe, "SKILL.md")
        if mem is not None and "SKILL.md" in mem and is_mem_text("SKILL.md", mem["SKILL.md"]) or mem is None and os.path.isfile(so) and is_text_file(so):
            d0 = frontmatter_rest((Text(None, mem["SKILL.md"]) if mem is not None else read_text(so)).lines)
            d1 = frontmatter_rest(read_text(ss).lines) if os.path.isfile(ss) and is_text_file(ss) else None
            if d0 != d1:
                problems.append("SKILL.md: frontmatter (description) differs from the original")
    p2 = not problems
    print(f"Proof 1 (re-scan {mode}): {'PASS' if p1 else 'FAIL'} · C={c.get('CRITICAL', 0)} H={c.get('HIGH', 0)} M={c.get('MEDIUM', 0)} L={c.get('LOW', 0)}")
    for f in left[:10]:
        print(f"  left: {f['severity']} {f['file']}:{f['line']} {f['rule_id']}")
    print(f"Proof 2 (purpose/diff): {'PASS' if p2 else 'FAIL'} · listed fixes: {len(fixes)}")
    for p in problems:
        print(f"  {p}")
    print("VERIFY: " + ("PASS" if p1 and p2 else "FAIL (do not offer install)"))
    return 0 if p1 and p2 else 1


def main():
    ap = argparse.ArgumentParser(prog="fix.py", description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="cmd", required=True)
    p = sub.add_parser("plan"); p.add_argument("src"); p.add_argument("--review"); p.add_argument("--include-low", action="store_true"); p.add_argument("--json", action="store_true")
    p = sub.add_parser("apply"); p.add_argument("src"); p.add_argument("--out"); p.add_argument("--review"); p.add_argument("--include-low", action="store_true"); p.add_argument("--source"); p.add_argument("--sha")
    p = sub.add_parser("record"); p.add_argument("safe"); p.add_argument("--file", required=True); p.add_argument("--line", type=int, required=True)
    p.add_argument("--rule", required=True); p.add_argument("--note", required=True); p.add_argument("--end-line", type=int); p.add_argument("--kind", choices=["judgment", "condition"], default="judgment")
    p = sub.add_parser("verify"); p.add_argument("src"); p.add_argument("safe"); p.add_argument("--review"); p.add_argument("--include-low", action="store_true")
    a = ap.parse_args()
    sys.exit({"plan": cmd_plan, "apply": cmd_apply, "record": cmd_record, "verify": cmd_verify}[a.cmd](a))


if __name__ == "__main__":
    main()
