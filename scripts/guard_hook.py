#!/usr/bin/env python3
"""skill-guard: Claude Code PreToolUse hook (CARD-SPEC.md section 11).

Stops installs/enables of skills, plugins, MCP servers and hooks that were not audited,
and asks a human to confirm every install and config change. A guardrail, not a sandbox.
Stdlib only, no network. Allowed calls print nothing and exit 0.
Run: python3 -I -B guard_hook.py   (hook JSON on stdin)
"""
import os
import sys

KEYWORDS = ("skills", "plugin", "mcp", ".claude", "marketplace", "hooks", "claude_desktop")
WRITE_TOOLS = ("Write", "Edit", "MultiEdit", "NotebookEdit")
OWN_DIR_PARTS = (".claude", "skills", "skill-security-audit")
OWN_FILES = ("audit-log.md", "audit-cache.json", "cost-log.jsonl", "calibration.json")
FACTORY = "obsidian vault/projects/03 skills-plugins factory/"
STALE_DAYS = 7
HOME = os.environ.get("HOME") or os.path.expanduser("~")
LOG_DIR = os.path.join(HOME, ".claude", "skills", "skill-security-audit")


def emit(decision, reason):
    import json
    print(json.dumps({"hookSpecificOutput": {
        "hookEventName": "PreToolUse",
        "permissionDecision": decision,
        "permissionDecisionReason": reason}}))


def log(tool, decision, source, reason, cmd=""):
    try:
        import json
        import time
        line = {"time": time.strftime("%Y-%m-%dT%H:%M:%S%z"), "tool": tool, "decision": decision,
                "source": source, "reason": reason, "cmd": cmd[:200]}
        with open(os.path.join(LOG_DIR, "guard-log.jsonl"), "a", encoding="utf-8") as f:
            f.write(json.dumps(line) + "\n")
    except Exception:
        pass


def finish(tool, decision, source, reason, cmd=""):
    log(tool, decision, source, reason, cmd)
    emit(decision, reason)
    sys.exit(0)


def main():
    raw = sys.stdin.read()
    # Pre-parse fast path: no keyword anywhere in the raw JSON (and no backslash-u escapes that could hide one).
    if "\\u" not in raw and not any(k in raw.lower() for k in KEYWORDS) \
            and '"tool_name"' in raw and raw.lstrip().startswith("{") and raw.rstrip().endswith("}"):
        return
    try:
        import json
        data = json.loads(raw)
        tool = data["tool_name"]
        ti = data.get("tool_input") or {}
    except Exception:
        finish("?", "ask", "", "skill-guard could not check this call")
    try:
        if tool == "Bash":
            text = str(ti.get("command", ""))
        elif tool in WRITE_TOOLS:
            text = str(ti.get("file_path") or ti.get("notebook_path") or "")
        else:
            return
        low = text.lower()
        if not any(k in low for k in KEYWORDS):
            return  # fast path
        res = check_bash(text) if tool == "Bash" else check_write(text)
    except SystemExit:
        raise
    except Exception:
        finish(tool, "ask", "", "skill-guard could not check this call", str(ti.get("command", "")))
    if res:
        finish(tool, res[0], res[1], res[2], text)


# ---------- shared helpers ----------
def expand(p):
    import posixpath
    p = p.strip()
    for pre in ("${HOME}", "$HOME", "~"):
        if p == pre or p.startswith(pre + "/"):
            p = HOME + p[len(pre):]
            break
    return posixpath.normpath(p) if p else p


def folders_re():
    import re
    return re.compile(r"(^|/)\.claude/(skills|agents|commands|plugins|hooks)(/|$)")


def check_write(path):
    import re
    import posixpath
    p = expand(path).lower()
    base = posixpath.basename(p)
    if posixpath.dirname(p) == posixpath.join(HOME, *OWN_DIR_PARTS).lower() and base in OWN_FILES:
        return None
    if (re.search(r"(^|/)\.claude/settings[^/]*\.json$", p)
            or base in (".mcp.json", ".claude.json", "claude_desktop_config.json")):
        return ("ask", path, "Config change: %s. Confirm you want this edit." % path)
    if folders_re().search(p):
        return ("ask", path, "Write into a skills/agents/commands/plugins/hooks folder: %s. "
                "Confirm it comes from an audited source." % path)
    return None


# ---------- audit log ----------
def load_rows():
    import re
    rows = []
    try:
        with open(os.path.join(LOG_DIR, "audit-log.md"), encoding="utf-8") as f:
            for i, line in enumerate(f):
                if not line.startswith("|"):
                    continue
                c = [x.strip() for x in line.strip().strip("|").split("|")]
                if len(c) >= 4 and re.match(r"\d{4}-\d{2}-\d{2}$", c[0]):
                    rows.append((c[0], i, c[1], c[2], c[3].replace("*", "").upper()))
    except OSError:
        pass
    rows.sort()
    return rows


def norm_source(s):
    """-> (key, ref, kind). kind 'repo' = github owner/repo; 'name' = bare/plugin name; else 'other'."""
    import re
    s = s.strip().strip("'\"").lower()
    ref = None
    if "#" in s:
        s, ref = s.split("#", 1)
    s = s.rstrip("/")
    if s.endswith(".git"):
        s = s[:-4]
    m = re.match(r"^(?:https?://(?:www\.)?github\.com/|git@github\.com:|github:)([^/\s@]+)/([^/\s@]+)", s)
    if m:
        rest = s[m.end():]
        if rest.startswith("@") and ref is None:
            ref = rest[1:]
        return (m.group(1) + "/" + m.group(2), ref, "repo")
    m = re.match(r"^([\w.-]+/[\w.-]+?)(?:@([^/\s]+))?$", s)
    if m and not s.startswith((".", "/", "~")) and "://" not in s:
        return (m.group(1), ref or m.group(2), "repo")
    if "/" not in s and "://" not in s:
        return (s, ref, "name")
    return (s, ref, "other")


def cand_keys(raw):
    import posixpath
    key, ref, kind = norm_source(raw)
    keys = {key}
    if kind == "name":
        keys.add(key.split("@")[0])
    elif kind == "other":
        base = posixpath.basename(key.rstrip("/"))
        if base:
            keys.add(base)
    return key, ref, kind, keys


def row_keys(row):
    import posixpath
    src = row[3]
    left, sha = src, ""
    if "@" in src:
        l2, r2 = src.rsplit("@", 1)
        if "/" in l2 or "://" in l2:
            left, sha = l2, r2
    key, _, kind = norm_source(left)
    keys = {key, row[2].lower()}
    if kind != "repo":
        keys.add(posixpath.basename(key.rstrip("/")))
    return keys, sha.strip().lower()


def lookup(cands, ref_flag=None):
    """-> (decision, source, reason) for the first candidate that has an audit row."""
    import datetime
    rows = load_rows()
    first = cands[0] if cands else ""
    for raw in cands:
        key, ref, kind, keys = cand_keys(raw)
        ref = ref_flag or ref
        hit = None
        for row in rows:  # sorted oldest -> newest, newest wins
            rk, sha = row_keys(row)
            if keys & rk:
                hit = (row, sha)
        if not hit:
            continue
        row, sha = hit
        date, _, skill, src, verdict = row
        if not verdict.startswith("APPROVE"):
            return ("deny", raw, "No approved audit for %s (latest verdict: %s). Run skill-security-audit first." % (raw, verdict))
        age = (datetime.date.today() - datetime.date.fromisoformat(date)).days
        if age > STALE_DAYS:
            return ("deny", raw, "Audit for %s is stale (%s, %d days old): re-audit, the source may have changed." % (raw, date, age))
        if ref and kind == "repo" and sha and not (sha.startswith(ref) or ref.startswith(sha)):
            return ("deny", raw, "Audited %s, installing %s. Re-audit that ref first." % (sha, ref))
        return ("ask", raw, "Audited %s: %s for %s. Confirm to install." % (date, verdict, src))
    return ("deny", first, "No approved audit for %s. Run skill-security-audit first." % (first or "this source"))


# ---------- bash ----------
OPS = set("();|&")
VALUE_FLAGS = {"-a", "--agent", "-s", "--skill", "-b", "--branch", "-d", "--dir", "--target", "--scope"}


def tokenize(cmd):
    import shlex
    cmd = cmd.replace("\\\n", " ").replace("\n", " ; ")
    lex = shlex.shlex(cmd, posix=True, punctuation_chars=True)
    lex.whitespace_split = True
    lex.commenters = ""
    segs, cur = [], []
    for t in lex:
        if set(t) <= OPS:
            if cur:
                segs.append(cur)
            cur = []
        else:
            cur.append(t)
    if cur:
        segs.append(cur)
    return segs


def split_redirs(words):
    out, redirs, i = [], [], 0
    while i < len(words):
        w = words[i]
        if w and set(w) <= set("<>"):
            if w in (">", ">>") and i + 1 < len(words):
                redirs.append(words[i + 1])
            i += 2
            continue
        out.append(w)
        i += 1
    return out, redirs


def strip_prefix(words):
    import re
    while words:
        w = words[0].lower()
        if w == "sudo":
            words = words[1:]
            while words and words[0].startswith("-"):
                skip = words[0] in ("-u", "-g", "-h", "-p", "-C", "-D", "-R", "-T")
                words = words[2:] if skip else words[1:]
        elif w == "env":
            words = words[1:]
            while words and (words[0].startswith("-") or re.match(r"^\w+=", words[0])):
                words = words[1:]
        elif w in ("command", "nohup", "time", "exec", "builtin") or re.match(r"^[A-Za-z_]\w*=", words[0]):
            words = words[1:]
        else:
            break
    return words


def positionals(args):
    out, i = [], 0
    while i < len(args):
        a = args[i]
        if a.startswith("-"):
            if a in VALUE_FLAGS and "=" not in a:
                i += 1
        else:
            out.append(a)
        i += 1
    return out


def flag_value(args, names):
    for i, a in enumerate(args):
        for n in names:
            if a == n and i + 1 < len(args):
                return args[i + 1]
            if a.startswith(n + "="):
                return a.split("=", 1)[1]
    return None


def is_own_build(paths):
    return bool(paths) and all(FACTORY in expand(p).lower() + "/" for p in paths)


def seg_result(words, redirs, depth):
    import posixpath
    import re
    words = strip_prefix(words)
    if not words:
        return None
    cmd = posixpath.basename(words[0]).lower()
    args = words[1:]
    fre = folders_re()
    under = lambda p: bool(fre.search(expand(p).lower()))
    unk = ("ask", "", "skill-guard couldn't identify the source; make sure it was audited.")

    if cmd in ("bash", "sh", "zsh", "dash") and depth < 3:
        for i, a in enumerate(args):
            if re.match(r"^-\w*c$", a) and i + 1 < len(args):
                return check_bash(args[i + 1], depth + 1)
        return None

    # npx/pnpx/bunx/pnpm dlx/yarn dlx ... skills add|install
    runner = cmd in ("npx", "pnpx", "bunx") or (cmd in ("pnpm", "yarn") and args[:1] == ["dlx"])
    if runner:
        rest = args[1:] if cmd in ("pnpm", "yarn") else args
        j = 0
        while j < len(rest) and rest[j].startswith("-"):
            j += 1
        if j < len(rest) and re.match(r"^skills(@\S+)?$", rest[j].lower()) \
                and j + 1 < len(rest) and rest[j + 1].lower() in ("add", "install"):
            tail = rest[j + 2:]
            if any(a.lower() in ("-y", "--yes") for a in args):
                return ("deny", "", "Auto-confirm skips the audit; run it without -y after the audit.")
            pos = positionals(tail)
            if not pos:
                return unk
            return lookup([pos[0]], flag_value(tail, ["--ref"]))
        return None

    if cmd == "claude" and args:
        sub = args[0].lower()
        if sub in ("plugin", "plugins") and len(args) > 1:
            verb = args[1].lower()
            if verb == "marketplace" and len(args) > 2 and args[2].lower() == "add":
                pos = positionals(args[3:])
                return lookup([pos[0]], flag_value(args, ["--ref"])) if pos else unk
            if verb in ("install", "add", "enable"):
                pos = positionals(args[2:])
                return lookup([pos[0]], flag_value(args, ["--ref"])) if pos else unk
        if sub in ("mcp",) and len(args) > 1 and args[1].lower() in ("add", "add-json"):
            pos = [p for p in positionals(args[2:]) if len(p) >= 3 and p.lower() not in ("npx", "node", "uvx", "python", "python3", "npm")]
            if not pos:
                return unk
            cands = [pos[0]] + [p for p in pos[1:] if "://" in p or "/" in p or "@" in p]
            return lookup(cands)
        return None

    if cmd == "git" and args[:1] == ["clone"]:
        pos = positionals(args[1:])
        if pos and any(under(p) for p in pos[1:]):
            return lookup([pos[0]])
        return None

    if cmd in ("cp", "mv", "rsync", "ln", "ditto", "install", "unzip", "tar"):
        pos = positionals(args)
        if cmd == "unzip":
            dest = flag_value(args, ["-d"])
            srcs = pos[:1]
        elif cmd == "tar":
            dest = flag_value(args, ["-C", "--directory"])
            srcs = [flag_value(args, ["-f", "--file"]) or (pos[0] if pos else "")]
        else:
            dest = pos[-1] if len(pos) >= 2 else None
            srcs = pos[:-1]
        if not dest or not under(dest):
            return None
        srcs = [s for s in srcs if s]
        if not srcs:
            return unk
        if is_own_build(srcs):
            return ("ask", srcs[0], "Syncing your own build from the vault. Confirm.")
        return lookup([expand(srcs[0])])

    if cmd in ("curl", "wget"):
        targets = list(redirs)
        for names in (["-o", "--output"], ["-O" if cmd == "wget" else "-o"], ["-P", "--directory-prefix", "--output-dir"]):
            v = flag_value(args, names)
            if v:
                targets.append(v)
        if any(under(t) for t in targets):
            urls = [a for a in args if "://" in a]
            return lookup(urls[:1]) if urls else unk
    return None


def check_bash(cmd, depth=0):
    results = []
    for words in tokenize(cmd):
        words, redirs = split_redirs(words)
        r = seg_result(words, redirs, depth)
        if r:
            results.append(r)
    for want in ("deny", "ask"):
        for r in results:
            if r[0] == want:
                return r
    return None


if __name__ == "__main__":
    main()
