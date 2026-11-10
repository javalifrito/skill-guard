#!/usr/bin/env python3
"""Tests for scripts/guard_hook.py (CARD-SPEC.md section 11).
Each case runs the hook as a subprocess with JSON on stdin and a temp HOME that has its own audit-log.md.
Run: python3 -I -B tests/test_guard_hook.py
"""
import datetime
import json
import os
import shutil
import statistics
import subprocess
import sys
import tempfile
import time

HERE = os.path.dirname(os.path.abspath(__file__))
HOOK = os.path.join(os.path.dirname(HERE), "scripts", "guard_hook.py")
today = datetime.date.today()
fresh = today.isoformat()
old = (today - datetime.timedelta(days=10)).isoformat()
SHA = "abc1234def5678"

LOG = """# Skill audit log

| Date | Skill | Source@SHA | Verdict | Top reason |
|---|---|---|---|---|
| {fresh} | good | okuser/good@{sha} | APPROVE | clean |
| {fresh} | cond | condo/cond@{sha} | APPROVE WITH CONDITIONS | pin sha |
| {fresh} | bad | evil/bad@{sha} | REJECT | exfil |
| {old} | stale | stale/stale@{sha} | APPROVE | clean |
| {old} | flip | flip/flip@{sha} | REJECT | old reject |
| {fresh} | flip | flip/flip@{sha} | APPROVE | fixed |
| {fresh} | myplug | myplug@mkt | APPROVE | clean |
""".format(fresh=fresh, old=old, sha=SHA)

TMP = tempfile.mkdtemp(prefix="guardtest-")
HOME = os.path.join(TMP, "home")
os.makedirs(os.path.join(HOME, ".claude", "skills", "skill-security-audit"))
with open(os.path.join(HOME, ".claude", "skills", "skill-security-audit", "audit-log.md"), "w") as f:
    f.write(LOG)
ENV = {"HOME": HOME, "PATH": os.environ.get("PATH", "")}
OWN = HOME + "/.claude/skills/skill-security-audit/"


def run(tool, ti, raw=None):
    stdin = raw if raw is not None else json.dumps({"tool_name": tool, "tool_input": ti})
    t = time.perf_counter()
    p = subprocess.run([sys.executable, "-I", "-B", HOOK], input=stdin, capture_output=True,
                       text=True, env=ENV, timeout=20)
    dt = (time.perf_counter() - t) * 1000
    out = p.stdout.strip()
    dec = reason = None
    if out:
        o = json.loads(out)["hookSpecificOutput"]
        assert o["hookEventName"] == "PreToolUse"
        dec, reason = o["permissionDecision"], o["permissionDecisionReason"]
    return p.returncode, dec, reason, dt


def bash(c):
    return ("Bash", {"command": c})


VAULT_SRC = HOME + "/Documents/Obsidian Vault/Projects/03 Skills-plugins factory/02 foo"
CASES = [
    ("-y -> deny", bash("npx skills add okuser/good -y"), "deny"),
    ("--yes -> deny", bash("npx -y skills@latest add okuser/good --yes"), "deny"),
    ("unaudited npx skills add -> deny", bash("npx skills add a/b"), "deny"),
    ("approved row -> ask", bash("npx skills add okuser/good"), "ask"),
    ("approve w/ conditions -> ask", bash("npx skills add condo/cond"), "ask"),
    ("REJECT -> deny", bash("npx skills add evil/bad"), "deny"),
    ("stale -> deny", bash("npx skills add stale/stale"), "deny"),
    ("newest row wins (old REJECT, new APPROVE) -> ask", bash("npx skills add flip/flip"), "ask"),
    ("pinned SHA matches -> ask", bash("npx skills add okuser/good@" + SHA[:7]), "ask"),
    ("pinned SHA mismatch -> deny", bash("npx skills add okuser/good@deadbee"), "deny"),
    ("--ref mismatch -> deny", bash("npx skills add okuser/good --ref v9"), "deny"),
    ("github URL, approved -> ask", bash("npx skills add https://github.com/okuser/good"), "ask"),
    ("plugin install approved -> ask", bash("claude plugin install myplug@mkt"), "ask"),
    ("plugin install unaudited -> deny", bash("claude plugins install nope@mkt"), "deny"),
    ("marketplace add unaudited -> deny", bash("claude plugin marketplace add x/y"), "deny"),
    ("mcp add unaudited -> deny", bash("claude mcp add foo -- npx -y foo-mcp"), "deny"),
    ("git clone into ~/.claude/skills unaudited -> deny", bash("git clone https://github.com/x/y ~/.claude/skills/y"), "deny"),
    ("git clone elsewhere -> no output", bash("git clone https://github.com/x/y /tmp/y"), None),
    ("cp -r x ~/.claude/skills/x, no row -> deny", bash("cp -r x ~/.claude/skills/x"), "deny"),
    ("sudo env cp into skills -> deny", bash("sudo env A=1 cp -r x $HOME/.claude/skills/x"), "deny"),
    ("curl -o into skills, no row -> deny", bash("curl -o ~/.claude/skills/a/SKILL.md https://example.com/a"), "deny"),
    ("wget redirect/ -O into plugins -> deny", bash("wget -O ~/.claude/plugins/p.zip https://example.com/p.zip"), "deny"),
    ("unzip -d into skills, no row -> deny", bash("unzip a.zip -d ~/.claude/skills"), "deny"),
    ("cp from vault factory -> ask", bash('cp -r "%s" ~/.claude/skills/foo' % VAULT_SRC), "ask"),
    ("cp from skills (copy out) -> no output", bash("cp -r ~/.claude/skills/foo /tmp/foo"), None),
    ("chained cd && npx skills add -y -> deny", bash("cd x && npx skills add a/b -y"), "deny"),
    ("semicolon/pipe chain -> deny", bash("echo hi; echo y | npx skills add a/b"), "deny"),
    ("bash -c wrapper -> deny", bash("bash -c 'npx skills add a/b -y'"), "deny"),
    ("uppercase NPX SKILLS ADD -> deny", bash("NPX SKILLS ADD a/b"), "deny"),
    ("Write ~/.claude/settings.json -> ask", ("Write", {"file_path": HOME + "/.claude/settings.json"}), "ask"),
    ("Edit settings.local.json -> ask", ("Edit", {"file_path": "/proj/.claude/settings.local.json"}), "ask"),
    ("Write .mcp.json -> ask", ("Write", {"file_path": "/proj/.mcp.json"}), "ask"),
    ("Write claude_desktop_config.json -> ask", ("Write", {"file_path": "/x/Claude/claude_desktop_config.json"}), "ask"),
    ("Write ~/.claude.json -> ask", ("Write", {"file_path": HOME + "/.claude.json"}), "ask"),
    ("Write own audit-log.md -> no output", ("Write", {"file_path": OWN + "audit-log.md"}), None),
    ("Edit own cost-log.jsonl -> no output", ("Edit", {"file_path": OWN + "cost-log.jsonl"}), None),
    ("Write own SKILL.md -> ask", ("Write", {"file_path": OWN + "SKILL.md"}), "ask"),
    ("Write new skill file -> ask", ("Write", {"file_path": HOME + "/.claude/skills/new/SKILL.md"}), "ask"),
    ("Write ~/.claude/hooks/x.sh -> ask", ("MultiEdit", {"file_path": HOME + "/.claude/hooks/x.sh"}), "ask"),
    ("Write unrelated file -> no output", ("Write", {"file_path": "/tmp/notes.md"}), None),
    ("Read tool -> no output", ("Read", {"file_path": HOME + "/.claude/settings.json"}), None),
    ("unrelated ls -> no output", bash("ls -la"), None),
    ("mentions skills but harmless -> no output", bash("ls ~/.claude/skills"), None),
    ("malformed JSON -> ask", None, "ask"),
    ("empty stdin -> ask", "", "ask"),
    ("missing tool_name -> ask", "{}", "ask"),
    ("unbalanced quote -> ask", bash("echo 'skills"), "ask"),
]

fails = 0
for name, case, want in CASES:
    if case is None:
        res = run(None, None, raw="{not json")
    elif isinstance(case, str):
        res = run(None, None, raw=case)
    else:
        res = run(*case)
    rc, dec, reason, _ = res
    ok = rc == 0 and dec == want and (dec is None or bool(reason))
    if name == "malformed JSON -> ask" or "stdin" in name or "missing" in name:
        ok = ok and "could not check" in (reason or "")
    if not ok:
        fails += 1
    print("%s  %s%s" % ("PASS" if ok else "FAIL", name, "" if ok else "  [got rc=%s %s: %s]" % (rc, dec, reason)))

# reason texts
rc, dec, reason, _ = run(*bash("npx skills add okuser/good"))
ok = "Audited %s: APPROVE for okuser/good@%s. Confirm to install." % (fresh, SHA) == reason
print("%s  ask reason text" % ("PASS" if ok else "FAIL")); fails += not ok
rc, dec, reason, _ = run(*bash("npx skills add a/b"))
ok = reason.startswith("No approved audit for a/b")
print("%s  deny reason text" % ("PASS" if ok else "FAIL")); fails += not ok

# guard-log.jsonl written, command truncated to 200 chars
lp = os.path.join(HOME, ".claude", "skills", "skill-security-audit", "guard-log.jsonl")
run(*bash("npx skills add a/b " + "x" * 400))
try:
    rows = [json.loads(l) for l in open(lp)]
    ok = len(rows) > 10 and all({"time", "tool", "decision", "source", "reason"} <= set(r) for r in rows) \
        and all(len(r["cmd"]) <= 200 for r in rows) and all(r["decision"] in ("ask", "deny") for r in rows)
except Exception as e:
    ok = False
print("%s  guard-log.jsonl written" % ("PASS" if ok else "FAIL")); fails += not ok

# fast-path timing: median of 20 runs. Wall time includes interpreter start-up, which is slow on some
# machines (sandboxes, antivirus: even an empty script file can take 400+ ms there), so the hook is judged by
# its overhead over an empty script (median of 20 interleaved runs) and by its own CPU time.
import resource


def cpu():
    r = resource.getrusage(resource.RUSAGE_CHILDREN)
    return (r.ru_utime + r.ru_stime) * 1000


EMPTY = os.path.join(TMP, "empty.py")
open(EMPTY, "w").write("import sys\nsys.stdin.read()\n")
hook_t, base_t, hook_c, base_c = [], [], [], []
for _ in range(20):
    c0 = cpu()
    hook_t.append(run(*bash("ls -la"))[3])
    c1 = cpu()
    t = time.perf_counter()
    subprocess.run([sys.executable, "-I", "-B", EMPTY], input="{}", text=True, env=ENV, capture_output=True)
    base_t.append((time.perf_counter() - t) * 1000)
    base_c.append(cpu() - c1)
    hook_c.append(c1 - c0)
med, base = statistics.median(hook_t), statistics.median(base_t)
cmed, cbase = statistics.median(hook_c), statistics.median(base_c)
print("INFO  fast path wall: median %.1f ms (min %.1f, max %.1f); empty-script start-up median %.1f ms; overhead %.1f ms"
      % (med, min(hook_t), max(hook_t), base, med - base))
print("INFO  fast path CPU: median %.1f ms; empty script %.1f ms; overhead %.1f ms" % (cmed, cbase, cmed - cbase))
ok = (cmed - cbase) < 50  # gate on CPU only; wall time is noisy under load (INFO above)
print("%s  fast path CPU overhead over an empty script < 50 ms" % ("PASS" if ok else "FAIL"))
fails += not ok

shutil.rmtree(TMP, ignore_errors=True)
print("\n%d failed" % fails if fails else "\nall passed")
sys.exit(1 if fails else 0)
