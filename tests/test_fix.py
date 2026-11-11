#!/usr/bin/env python3
"""Tests for fix.py (CARD-SPEC §12). Stdlib only.
Run: python3 -I -B "<skill>/tests/test_fix.py"   Prints PASS/FAIL per test; exit 1 on any failure.
Works on copies in a temp dir (removed afterwards). The malicious samples are only read from the encoded bundle
(tests/fixtures/attack-bundle.json) in memory; attack text is never written to disk. Never executes anything.
"""
import base64, hashlib, json, os, shutil, stat, subprocess, sys, tempfile, zlib

HERE = os.path.dirname(os.path.abspath(__file__))
D = os.path.dirname(HERE)
FIX = os.path.join(D, "scripts", "fix.py")
SCAN = os.path.join(D, "scripts", "scan.py")
FIXABLE = os.path.join(HERE, "fixtures", "fixable")
BUNDLE = os.path.join(HERE, "fixtures", "attack-bundle.json")
SAMPLE = f"bundle:{BUNDLE}#malicious-sample"
TP = f"bundle:{BUNDLE}#true-positives"  # append "/<subdir-or-file>" to select a subtree


def load_set(name):  # copy of the bundle decoder (not imported on purpose); decodes in memory only
    blob = json.load(open(BUNDLE, encoding="utf-8"))["sets"][name]
    return json.loads(zlib.decompress(base64.b64decode(blob)).decode("utf-8"))

SKILL_MD = os.path.join(D, "SKILL.md")
SKILL_MD_BYTES_BEFORE = 9066
DESC = "description: MANDATORY before installing/enabling/trusting any shared skill"


def run(*args):
    return subprocess.run([sys.executable, "-I", "-B", FIX] + list(args), capture_output=True, text=True, encoding="utf-8")


def snapshot(root):
    out = {}
    for d, dirs, files in os.walk(root):
        for n in files:
            p = os.path.join(d, n)
            out[os.path.relpath(p, root)] = (hashlib.sha256(open(p, "rb").read()).hexdigest(), stat.S_IMODE(os.lstat(p).st_mode))
    return out


def fresh(tmp, name="fixable"):
    dst = os.path.join(tmp, name)
    shutil.copytree(FIXABLE, dst, symlinks=True)
    os.chmod(os.path.join(dst, "references", "template.txt"), 0o755)  # in case a copy lost the bit
    return dst


def read(p):
    return open(p, encoding="utf-8").read()


def plan_json(*args):
    r = run("plan", *args, "--json")
    assert r.returncode == 0, r.stderr
    return json.loads(r.stdout)


def test_plan_patch(tmp):
    src = fresh(tmp)
    p = plan_json(src)
    assert p["route"] == "patch", p["route"]
    rules = {m["rule_id"] for m in p["mechanical"]}
    for need in ("injection.invisible-bidi-tag-unicode", "injection.html-comment", "ads.advertising-affiliate-content",
                 "fix.auto-confirm-flag", "filesystem.file-is-executable"):
        assert need in rules, f"{need} missing from mechanical: {rules}"
    j = {(g["file"], g["line"]) for g in p["judgment"]}
    assert ("SKILL.md", 12) in j and ("scripts/digest.py", 10) in j, j
    assert p["cost"]["tokens"] > 0 and p["cost"]["kind"] == "fix"
    txt = run("plan", src).stdout
    assert txt.startswith("Route: patch") and "Cost: Fix" in txt, txt


def test_apply_and_original_untouched(tmp):
    src = fresh(tmp)
    before = snapshot(src)
    out = os.path.join(tmp, "fixable-safe")
    r = run("apply", src, "--out", out)
    assert r.returncode == 0, r.stdout + r.stderr
    assert snapshot(src) == before, "original changed"
    md = read(os.path.join(out, "SKILL.md"))
    assert "​" not in md and "<!--" not in md and "promo code" not in md and " -y" not in md, md
    assert "name: fixable-demo-safe" in md
    assert "npx skills add some-helper" in md and "npx digest-tool" in md  # untouched judgment items
    assert not os.stat(os.path.join(out, "references", "template.txt")).st_mode & 0o111, "exec bit kept"
    prov = json.load(open(os.path.join(out, "provenance.json")))
    for k in ("source", "sha", "route", "created", "original_hashes", "fixes", "rescan", "auto_update", "upstream"):
        assert k in prov, k
    assert prov["route"] == "patch" and prov["auto_update"] is False
    assert prov["rescan"]["counts"].get("CRITICAL", 0) == 0 and prov["rescan"]["counts"].get("HIGH", 0) == 0
    assert set(prov["original_hashes"]) == set(before)
    assert all(f["kind"] in ("mechanical", "judgment", "removed-file", "rebuild") for f in prov["fixes"])
    assert any(f["rule_id"] == "injection.html-comment" and "paid plan" in f["before"] for f in prov["fixes"])
    assert not os.path.exists(os.path.join(out, ".git"))


def test_verify_flow(tmp):
    src = fresh(tmp)
    out = os.path.join(tmp, "fixable-safe")
    assert run("apply", src, "--out", out).returncode == 0
    r = run("verify", src, out)
    assert r.returncode == 0, r.stdout  # mechanical fixes alone are all listed
    p = os.path.join(out, "SKILL.md")
    s = read(p)
    assert "npx digest-tool --input" in s
    open(p, "w", encoding="utf-8").write(s.replace("npx digest-tool --input", "npx digest-tool@1.2.3 --input"))
    r = run("verify", src, out)
    assert r.returncode == 1 and "unlisted change" in r.stdout and "SKILL.md:12" in r.stdout, r.stdout
    r = run("record", out, "--file", "SKILL.md", "--line", "12", "--rule", "rce.runs-a-package-fetched-at-runtime", "--note", "pinned")
    assert r.returncode == 0, r.stderr
    r = run("verify", src, out)
    assert r.returncode == 0, r.stdout
    prov = json.load(open(os.path.join(out, "provenance.json")))
    rec = [f for f in prov["fixes"] if f["kind"] == "judgment"]
    assert rec and "digest-tool@1.2.3" in rec[0]["after"] and "digest-tool --input" in rec[0]["before"], rec
    # a second edit in another file (drop the telemetry call) is also flagged until recorded
    dp = os.path.join(out, "scripts", "digest.py")
    d = read(dp)
    open(dp, "w", encoding="utf-8").write("\n".join(l for l in d.split("\n") if "telemetry.example" not in l))
    r = run("verify", src, out)
    assert r.returncode == 1 and "scripts/digest.py" in r.stdout, r.stdout
    assert run("record", out, "--file", "scripts/digest.py", "--line", "10", "--rule", "exfil.sends-data-over-http", "--note", "dropped telemetry").returncode == 0
    assert run("verify", src, out).returncode == 0


def test_verify_description_and_added_file(tmp):
    src = fresh(tmp)
    out = os.path.join(tmp, "fixable-safe")
    assert run("apply", src, "--out", out).returncode == 0
    p = os.path.join(out, "SKILL.md")
    s = read(p)
    open(p, "w", encoding="utf-8").write(s.replace("weekly digest", "weekly digest and more"))
    r = run("verify", src, out)
    assert r.returncode == 1 and "frontmatter" in r.stdout, r.stdout
    open(p, "w", encoding="utf-8").write(s)
    open(os.path.join(out, "extra.sh"), "w").write("echo hi\n")
    r = run("verify", src, out)
    assert r.returncode == 1 and "extra.sh" in r.stdout and "added" in r.stdout, r.stdout


def test_verify_fails_on_left_high(tmp):
    src = fresh(tmp)
    out = os.path.join(tmp, "fixable-safe")
    assert run("apply", src, "--out", out).returncode == 0
    p = os.path.join(out, "scripts", "digest.py")
    open(p, "a", encoding="utf-8").write("\nexec('print(1)')\n")
    r = run("verify", src, out)
    assert r.returncode == 1 and "Proof 1" in r.stdout and "FAIL" in r.stdout, r.stdout


def test_rebuild_malicious_sample(tmp):
    p = plan_json(SAMPLE)
    assert p["route"] == "rebuild" and p["cost"]["kind"] == "rebuild" and not p["mechanical"], p
    out = os.path.join(tmp, "malicious-safe")
    r = run("apply", SAMPLE, "--out", out)
    assert r.returncode == 3, (r.returncode, r.stdout, r.stderr)
    assert not os.path.exists(out), "rebuild route must not write a patched copy"
    assert "Route: rebuild" in run("plan", SAMPLE).stdout


def test_rebuild_true_positives(tmp):
    for name in ("curl-pipe", "override"):
        spec = f"{TP}/{name}"
        assert plan_json(spec)["route"] == "rebuild", name
        out = os.path.join(tmp, name + "-safe")
        assert run("apply", spec, "--out", out).returncode == 3, name
        assert not os.path.exists(out), name
    # secret sent over the network (HIGH, malicious-intent rule) -> rebuild
    assert plan_json(f"{TP}/token-send.sh")["route"] == "rebuild"
    # an unpinned npx alone is a patch
    assert plan_json(f"{TP}/npx-latest")["route"] == "patch"


def test_bundle_patch_refused(tmp):
    out = os.path.join(tmp, "npx-safe")
    r = run("apply", f"{TP}/npx-latest", "--out", out)
    assert r.returncode == 2 and "bundle targets are test samples; patch a real folder" in r.stderr, (r.returncode, r.stderr)
    assert not os.path.exists(out) and os.listdir(tmp) == [], "apply on a bundle target wrote something"
    r = run("plan", f"{TP}/nope")
    assert r.returncode == 2 and "selects no files" in r.stderr, r.stderr


def test_verify_bundle_src(tmp):
    orig = load_set("true-positives")["npx-latest/SKILL.md"]
    safe = os.path.join(tmp, "npx-safe")
    os.makedirs(safe)
    with open(os.path.join(safe, "provenance.json"), "w") as fh:
        json.dump({"fixes": []}, fh)
    with open(os.path.join(safe, "SKILL.md"), "w", encoding="utf-8") as fh:  # benign: the pinned version
        fh.write(orig.replace("npx foo@latest", "npx foo@1.2.3"))
    spec = f"{TP}/npx-latest"
    r = run("verify", spec, safe)
    assert r.returncode == 1 and "unlisted change" in r.stdout and "SKILL.md:7" in r.stdout, r.stdout
    assert run("record", safe, "--file", "SKILL.md", "--line", "7", "--rule", "rce.runs-a-package-fetched-at-runtime", "--note", "pinned").returncode == 0
    r = run("verify", spec, safe)
    assert r.returncode == 0 and "VERIFY: PASS" in r.stdout, r.stdout


def test_rebuild_verify(tmp):
    spec = f"{TP}/curl-pipe"
    safe = os.path.join(tmp, "new-safe")
    os.makedirs(safe)
    open(os.path.join(safe, "SKILL.md"), "w").write("---\nname: curl-pipe-safe\ndescription: fresh rewrite\n---\n# Steps\nDo the thing.\n")
    r = run("verify", spec, safe)
    assert r.returncode == 0, r.stdout
    # "identical to original": the whole set takes the rebuild route; copy one BENIGN member (zero-width.txt: plain text with an
    # invisible character) so no attack text is written. Proof 1 fails too on that file, but the copy must be named.
    open(os.path.join(safe, "copied.txt"), "w", encoding="utf-8").write(load_set("true-positives")["zero-width.txt"])
    r = run("verify", TP, safe)
    assert r.returncode == 1 and "identical to original" in r.stdout and "zero-width.txt" in r.stdout, r.stdout


def test_none_and_include_low(tmp):
    d = os.path.join(tmp, "lowonly")
    os.makedirs(d)
    open(os.path.join(d, "SKILL.md"), "w").write("---\nname: lowonly\ndescription: x\n---\nWe log usage telemetry counts only.\n")
    p = plan_json(d)
    assert p["route"] == "none", p
    assert run("apply", d, "--out", os.path.join(tmp, "lowonly-safe")).returncode == 4
    p = plan_json(d, "--include-low")
    assert p["route"] == "patch", p


def test_review_changes_route(tmp):
    scan = json.loads(subprocess.run([sys.executable, "-I", "-B", SCAN, BUNDLE, "--bundle", "--set=malicious-sample", "--json"], capture_output=True, text=True).stdout)
    review = {"dismiss": {f"{f['file']}:{f['line']}": "test" for f in scan["findings"] if f["severity"] != "INFO"}}
    rp = os.path.join(tmp, "review.json")
    json.dump(review, open(rp, "w"))
    assert plan_json(SAMPLE, "--review", rp)["route"] == "none"
    # re-level one CRITICAL down: the other CRITICALs still force rebuild
    key = f"{scan['findings'][0]['file']}:{scan['findings'][0]['line']}"
    json.dump({"level": {key: "LOW"}}, open(rp, "w"))
    assert plan_json(SAMPLE, "--review", rp)["route"] == "rebuild"


def test_apply_refusals(tmp):
    src = fresh(tmp)
    bad = os.path.join(os.path.expanduser("~"), ".claude", "skills", "__fix-test-safe")
    r = run("apply", src, "--out", bad)
    assert r.returncode == 2 and not os.path.exists(bad), r.stderr
    out = os.path.join(tmp, "occupied")
    os.makedirs(out)
    open(os.path.join(out, "x"), "w").write("x")
    assert run("apply", src, "--out", out).returncode == 2
    assert run("apply", src, "--out", os.path.join(src, "inner-safe")).returncode == 2
    # default output sits next to the audited copy
    assert run("apply", src).returncode == 0 and os.path.isdir(os.path.join(tmp, "fixable-demo-safe"))


def test_symlink_and_update_script(tmp):
    src = fresh(tmp)
    os.symlink("/etc/hosts", os.path.join(src, "references", "outside"))
    open(os.path.join(src, "scripts", "self-update.sh"), "w").write("echo update\n")
    out = os.path.join(tmp, "fixable-safe")
    p = plan_json(src)
    assert p["route"] == "patch" and {"filesystem.symlink", "fix.update-script"} <= {m["rule_id"] for m in p["mechanical"]}, p["mechanical"]
    before = snapshot(src)
    assert run("apply", src, "--out", out).returncode == 0
    assert not os.path.lexists(os.path.join(out, "references", "outside")) and not os.path.exists(os.path.join(out, "scripts", "self-update.sh"))
    assert os.path.islink(os.path.join(src, "references", "outside")) and snapshot(src) == before
    assert run("verify", src, out).returncode == 0


def test_static_and_skill_md(tmp):
    s = read(FIX)
    assert not any(l.startswith("from ") or l.startswith(("import card", "import scan")) for l in s.splitlines())
    allowed = {"argparse", "datetime", "difflib", "base64", "hashlib", "json", "math", "os", "re", "shutil", "stat", "subprocess", "sys", "zlib"}
    for ln in s.splitlines():
        if ln.startswith("import "):
            mods = {m.strip() for m in ln[7:].split(",")}
            assert mods <= allowed, mods
    assert "urllib" not in s and "socket" not in s
    sk = read(SKILL_MD)
    grow = os.path.getsize(SKILL_MD) - SKILL_MD_BYTES_BEFORE
    assert grow <= 900, f"SKILL.md grew {grow} bytes"
    assert sk.startswith("---\nname: skill-security-audit\n" + DESC), "frontmatter changed"
    assert "fix.py plan" in sk and "fix.py verify" in sk and "fix.py record" in sk and "fix.py apply" in sk


TESTS = [test_plan_patch, test_apply_and_original_untouched, test_verify_flow, test_verify_description_and_added_file,
         test_verify_fails_on_left_high, test_rebuild_malicious_sample, test_rebuild_true_positives, test_bundle_patch_refused,
         test_verify_bundle_src, test_rebuild_verify,
         test_none_and_include_low, test_review_changes_route, test_apply_refusals, test_symlink_and_update_script,
         test_static_and_skill_md]


def main():
    fails = 0
    for t in TESTS:
        tmp = tempfile.mkdtemp(prefix="fixtest-")
        try:
            t(tmp)
            print(f"PASS {t.__name__}")
        except Exception as e:  # noqa: BLE001
            fails += 1
            print(f"FAIL {t.__name__}: {type(e).__name__}: {str(e)[:600]}")
        finally:
            shutil.rmtree(tmp, ignore_errors=True)
    print(f"{len(TESTS) - fails}/{len(TESTS)} passed")
    sys.exit(1 if fails else 0)


if __name__ == "__main__":
    main()
