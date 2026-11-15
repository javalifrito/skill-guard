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
    ("Write own audit-log.md -> ask", ("Write", {"file_path": OWN + "audit-log.md"}), "ask"),
    ("Edit own audit-cache.json -> ask", ("Edit", {"file_path": OWN + "audit-cache.json"}), "ask"),
    ("Edit own cost-log.jsonl -> no output", ("Edit", {"file_path": OWN + "cost-log.jsonl"}), None),
    ("Write own calibration.json -> no output", ("Write", {"file_path": OWN + "calibration.json"}), None),
    # ---- S2 fallback: anything touching a protected place that is not clearly read-only -> ask ----
    ("redirect into skills -> ask", bash("echo hi > ~/.claude/skills/evil/SKILL.md"), "ask"),
    ("cd into skills then git clone -> ask", bash("cd ~/.claude/skills && git clone https://github.com/evil/x"), "ask"),
    ("python3 -c writing settings.json -> ask", bash("python3 -c \"open('%s/.claude/settings.json','w').write('{}')\"" % HOME), "ask"),
    ("python3 -c writing /Users/a path -> ask", bash("python3 -c \"open('/Users/a/.claude/settings.json','w').write('{}')\""), "ask"),
    ("node -e touching .claude -> ask", bash("node -e \"require('fs').rmSync('x/.claude/skills')\""), "ask"),
    ("perl -e touching .mcp.json -> ask", bash("perl -e 'unlink q(.mcp.json)'"), "ask"),
    ("osascript -e touching .claude -> ask", bash("osascript -e 'do shell script \"rm -rf ~/.claude/skills\"'"), "ask"),
    ("tee settings.json -> ask", bash("tee ~/.claude/settings.json < /tmp/x"), "ask"),
    ("dd of= into skills -> ask", bash("dd if=/tmp/x of=~/.claude/skills/a/SKILL.md"), "ask"),
    ("sed -i in skills -> ask", bash("sed -i s/a/b/ ~/.claude/skills/a/SKILL.md"), "ask"),
    ("touch in hooks -> ask", bash("touch ~/.claude/hooks/x.sh"), "ask"),
    ("mkdir in agents -> ask", bash("mkdir -p ~/.claude/agents/x"), "ask"),
    ("rm in skills -> ask", bash("rm -rf ~/.claude/skills/old"), "ask"),
    ("chmod in plugins -> ask", bash("chmod +x ~/.claude/plugins/x.sh"), "ask"),
    ("chown in commands -> ask", bash("chown me ~/.claude/commands/x.md"), "ask"),
    ("truncate settings -> ask", bash("truncate -s0 ~/.claude/settings.local.json"), "ask"),
    ("mv out of skills deletes it -> ask", bash("mv ~/.claude/skills/foo /tmp/foo"), "ask"),
    ("cp -t into skills -> ask", bash("cp -t ~/.claude/skills/x evil"), "ask"),
    ("find -delete in skills -> ask", bash("find ~/.claude/skills -name x -delete"), "ask"),
    ("find -exec in skills -> ask", bash("find ~/.claude/skills -exec rm {} ;"), "ask"),
    ("rm -rf ~/.claude (the folder itself) -> ask", bash("rm -rf ~/.claude"), "ask"),
    ("rm glob under .claude -> ask", bash("rm -rf ~/.claude/*"), "ask"),
    ("cd ~/.claude then rm -> ask", bash("cd ~/.claude && rm -rf skills"), "ask"),
    ("echo >> audit-log.md -> ask (audit message)", bash('echo "| 2026-11-15 | x | evil/x@abc | APPROVE | ok |" >> ~/.claude/skills/skill-security-audit/audit-log.md'), "ask"),
    ("redirect into .mcp.json -> ask", bash("echo {} > /proj/.mcp.json"), "ask"),
    ("&> redirect into skills -> ask", bash("ls &> ~/.claude/skills/x"), "ask"),
    ("redirect from read-only cmd -> ask", bash("cat /tmp/x > ~/.claude/skills/a/SKILL.md"), "ask"),
    ("bash -c inner redirect -> ask", bash("bash -c 'echo hi > ~/.claude/skills/a/SKILL.md'"), "ask"),
    ("sudo tee -> ask", bash("sudo tee ~/.claude/skills/a/SKILL.md"), "ask"),
    ("--mark-clean -> ask", bash("python3 -I %sscripts/scan.py /tmp/x --mark-clean" % OWN), "ask"),
    ("own script writing --out into skills -> ask", bash("python3 -I %sscripts/fix.py apply /tmp/x --out ~/.claude/skills/y" % OWN), "ask"),
    ("someone else's script on a skill path -> ask", bash("python3 /tmp/evil.py ~/.claude/skills/x"), "ask"),
    # ---- must stay silent ----
    ("cat settings.json -> no output", bash("cat ~/.claude/settings.json"), None),
    ("grep -r in skills -> no output", bash("grep -r foo ~/.claude/skills"), None),
    ("own scan.py -> no output", bash("python3 -I ~/.claude/skills/skill-security-audit/scripts/scan.py /tmp/x"), None),
    ("own scan.py on an installed skill -> no output", bash("python3 -I -B %sscripts/scan.py ~/.claude/skills/foo --json" % OWN), None),
    ("find without write flags -> no output", bash("find ~/.claude/skills -name SKILL.md"), None),
    ("ls/wc/head/tail/diff/stat/file/du/tree/rg -> no output",
     bash("ls ~/.claude/skills; wc -l ~/.claude/skills/a; head ~/.claude/skills/a; tail ~/.claude/skills/a; diff ~/.claude/skills/a /tmp/a; stat ~/.claude/skills; file ~/.claude/skills/a; du ~/.claude/skills; tree ~/.claude/skills; rg x ~/.claude/skills"), None),
    ("cd into skills then read-only commands -> no output", bash("cd ~/.claude/skills && ls && cat a/SKILL.md"), None),
    ("python3 -c unrelated -> no output", bash("python3 -c \"print('skills plugin')\""), None),
    ("no keyword at all -> no output", bash("echo hello > /tmp/x && rm /tmp/x"), None),
    ("keyword but not protected (skills in a project dir) -> no output", bash("rm -rf /tmp/skills/old"), None),
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
ok = "Audited %s at %s: APPROVE for okuser/good@%s. Confirm to install." % (fresh, SHA, SHA) == reason
print("%s  ask reason text" % ("PASS" if ok else "FAIL")); fails += not ok
rc, dec, reason, _ = run(*bash("npx skills add a/b"))
ok = reason.startswith("No approved audit for a/b")
print("%s  deny reason text" % ("PASS" if ok else "FAIL")); fails += not ok

rc, dec, reason, _ = run(*bash("echo hi > ~/.claude/skills/evil/SKILL.md"))
ok = reason == "This command changes Claude's skills, plugins or settings. Confirm you want it."
print("%s  fallback reason text" % ("PASS" if ok else "FAIL")); fails += not ok
rc, dec, reason, _ = run("Write", {"file_path": OWN + "audit-log.md"})
ok = reason == "Recording an audit result. Confirm it matches the verdict you were shown."
print("%s  audit-log write reason text" % ("PASS" if ok else "FAIL")); fails += not ok
rc, dec, reason, _ = run(*bash("python3 -I %sscripts/scan.py /tmp/x --mark-clean" % OWN))
ok = reason == "Recording an audit result. Confirm it matches the verdict you were shown."
print("%s  --mark-clean reason text" % ("PASS" if ok else "FAIL")); fails += not ok

# an approved row without a recorded SHA says so
with open(os.path.join(HOME, ".claude", "skills", "skill-security-audit", "audit-log.md"), "a") as f:
    f.write("| %s | nover | nover/nover | APPROVE | clean |\n" % fresh)
rc, dec, reason, _ = run(*bash("npx skills add nover/nover"))
ok = dec == "ask" and "at no version recorded" in reason
print("%s  no-version audit says 'no version recorded'" % ("PASS" if ok else "FAIL")); fails += not ok

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
