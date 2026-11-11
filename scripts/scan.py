#!/usr/bin/env python3
"""Static security scanner for Claude skills / plugins / MCP bundles (skill-guard v2).
Usage: python3 -I scan.py <dir|file|bundle.json|-> [--json] [--full] [--color] [--mark-clean]
                         [--exclude=<relpath>]... [--bundle [--set=<name>]]
--json: machine output (card.py / fix.py input). --full: verbose. Default: compact, deduplicated.
--color: ANSI gradient cost bar for a terminal (default is emoji, which also renders in chat/phone).
--exclude: skip a relative path (file or folder), e.g. --exclude=tests/fixtures. Listed in JSON "excluded".
--bundle: the target is an encoded test-sample bundle (tests/fixtures/attack-bundle.json, '-' = stdin), scanned in memory.
  --set=<name> scans one set and drops its prefix from file names. --mark-clean is refused on bundles (exit 64).
--mark-clean: only after a user-approved APPROVE; records file hashes in audit-cache.json.
Reads files only. Never executes anything from the target. Stdlib only, no network.
Exit code: 0 = no HIGH/CRITICAL, 1 = HIGH found, 2 = CRITICAL found, 64 = bad usage.
"""
import base64, hashlib, json, math, os, re, stat, sys, unicodedata, zlib
from collections import Counter

SEV_ORDER = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "INFO": 0}
LOWER = {"CRITICAL": "HIGH", "HIGH": "MEDIUM", "MEDIUM": "LOW", "LOW": "LOW", "INFO": "INFO"}

# (category, severity, regex, explanation). rule_id = category + slug(explanation head), see rule_id().
# These rows are detection patterns, not instructions: the self-audit flags them by design (README).
RULES = [
    # --- remote code execution / download-and-run
    ("rce", "CRITICAL", r"(curl|wget)[^\n|]*\|\s*(ba|z)?sh\b", "Downloads and pipes straight into a shell"),
    ("rce", "CRITICAL", r"base64\s+(-d|--decode)[^\n]*\|\s*(ba|z)?sh", "Decodes hidden payload into a shell"),
    ("rce", "CRITICAL", r"powershell[^\n]*-(e|enc|encodedcommand)\b", "Encoded PowerShell payload"),
    ("rce", "HIGH", r"(?<![\w.])(eval|exec)\s*\(", "Dynamic code execution (eval/exec)"),
    ("rce", "HIGH", r"\bnew\s+Function\s*\(|\bvm\.runIn", "Dynamic JS code execution"),
    ("rce", "HIGH", r"__import__\s*\(|importlib\.import_module|(?<![\w.])compile\s*\(", "Dynamic import/compile"),
    ("rce", "MEDIUM", r"subprocess\.|os\.system|os\.popen|child_process|execSync|spawn\(", "Runs shell commands"),
    ("rce", "MEDIUM", r"\b(npx|uvx|pipx run|bunx)\s+[^\s]+", "Runs a package fetched at runtime"),
    ("deps", "MEDIUM", r"\b(pip3?|npm|pnpm|yarn|gem|cargo|brew)\s+(install|add|i)\b", "Installs dependencies (check names/pins)"),
    ("deps", "HIGH", r"\"(pre|post)install\"\s*:", "npm install-time script (runs on install)"),
    # --- secrets / private data access
    ("secrets", "CRITICAL", r"~/?\.ssh|id_rsa|id_ed25519|authorized_keys", "Touches SSH keys"),
    ("secrets", "CRITICAL", r"\.aws/credentials|\.config/gcloud|\.kube/config|\.docker/config\.json|\.npmrc|\.pypirc|\.netrc|\.git-credentials", "Touches cloud/dev credentials"),
    ("secrets", "CRITICAL", r"\.claude/\.credentials|\.claude\.json|claude_desktop_config|anthropic_api_key", "Touches Claude credentials/config"),
    ("secrets", "CRITICAL", r"security\s+(find|dump)-(generic|internet)-password|dump-keychain|Keychains/", "Reads macOS Keychain"),
    ("secrets", "CRITICAL", r"(?-i:(Google/Chrome|Chromium|BraveSoftware|Microsoft Edge|Firefox/Profiles|\.mozilla/firefox|Arc/User Data)[^\n]*(Login Data|Cookies|Local State|Web Data|key4\.db|logins\.json|cookies\.sqlite)|key4\.db|logins\.json|cookies\.sqlite|Group Containers/[^\n]*1password|Application Support/(1Password|Bitwarden))", "Reads browser/password-manager stores"),
    ("secrets", "HIGH", r"(?-i:\bop (item get|read|document get)\b|\bbw (get|list|export)\b)", "Password manager CLI (reads stored secrets)"),
    ("secrets", "HIGH", r"\bprintenv\b(?!\s+\$?[A-Za-z_])|(?<![\w-])env\s*[|>]|dict\(os\.environ\)|os\.environ\.items\(\)|json\.dumps\(os\.environ|JSON\.stringify\(process\.env|Object\.(keys|entries)\(process\.env", "Dumps all environment variables"),
    ("secrets", "HIGH", r"^(?=[^\n]*((?-i:\b[A-Z0-9_]*(API_KEY|SECRET|TOKEN|PASSWORD)[A-Z0-9_]*\b)|\$\{?[A-Z_]*(TOKEN|KEY|SECRET)))(?=[^\n]*(\bcurl\b|\bwget\b|fetch\(|requests\.|axios|http\.request))", "Secret sent over network"),
    ("secrets", "LOW", r"(?-i:\b[A-Z0-9_]*(API_KEY|SECRET|TOKEN|PASSWORD)[A-Z0-9_]*\b)", "Mentions secrets/tokens (verify use)"),
    ("secrets", "MEDIUM", r"^(?!.*(--exclude|\.gitignore|!\.env|ignore)).*(^|[\s\"'/])\.env\b", "Reads .env files"),
    ("privacy", "HIGH", r"Library/Messages|chat\.db|AddressBook|Contacts|Photos Library|Library/Mail|\.bash_history|\.zsh_history", "Reads personal data (messages, contacts, mail, history)"),
    ("privacy", "MEDIUM", r"screencapture|pbpaste|clipboard|getUserMedia|keylog|pynput|CGEventTap", "Screen/clipboard/keyboard capture"),
    # --- exfiltration / third-party sharing
    ("exfil", "CRITICAL", r"discord(app)?\.com/api/webhooks|hooks\.slack\.com|api\.telegram\.org/bot", "Posts to chat webhook (classic exfil channel)"),
    ("exfil", "CRITICAL", r"pastebin\.com|transfer\.sh|ngrok\.io|requestbin|webhook\.site|pipedream\.net|interact\.sh|burpcollaborator|\boast\.(fun|live|site|online|me|pro)\b|\binteractsh\b", "Known exfil/tunnel/paste endpoint"),
    ("exfil", "HIGH", r"\b(nc|ncat|netcat|socat)\s+-|/dev/tcp/|socket\.socket\(", "Raw network socket / reverse shell pattern"),
    ("exfil", "MEDIUM", r"requests\.(post|put)|urllib\.request|fetch\(|axios\.|curl\s+[^\n]*(-d|--data|-F|-T|--upload)", "Sends data over HTTP"),
    ("exfil", "LOW", r"analytics|telemetry|tracking|mixpanel|segment\.io|posthog|sentry\.io|google-analytics", "Telemetry/analytics"),
    # --- persistence / backdoor
    ("backdoor", "CRITICAL", r"LaunchAgents|LaunchDaemons|launchctl\s+(load|bootstrap)|crontab\s|/etc/cron|systemctl\s+enable|schtasks", "Installs persistence (runs at boot/login)"),
    ("backdoor", "HIGH", r"\.(bashrc|zshrc|bash_profile|zprofile|profile)\b", "Edits shell startup files"),
    ("backdoor", "HIGH", r"\bsudo\b|chmod\s+[0-7]*[4-7][0-7]{3}|chmod\s+\+s|setuid", "Privilege escalation"),
    ("backdoor", "HIGH", r"osascript|tccutil|spctl\s+--master-disable|xattr\s+-d\s+com\.apple\.quarantine|csrutil", "Bypasses macOS security (Gatekeeper/TCC/quarantine)"),
    # --- Claude harness tampering
    ("claude-tamper", "CRITICAL", r"dangerously-skip-permissions|bypassPermissions|\"defaultMode\"\s*:\s*\"(bypass|acceptEdits)", "Disables Claude permission prompts"),
    ("claude-tamper", "HIGH", r"settings(\.local)?\.json|\"hooks\"\s*:|PreToolUse|PostToolUse|UserPromptSubmit|SessionStart", "Adds/edits Claude hooks or settings"),
    ("claude-tamper", "HIGH", r"\"permissions\"\s*:|\"allow\"\s*:\s*\[", "Grants itself tool permissions"),
    ("claude-tamper", "HIGH", r"CLAUDE\.md|\.claude/(skills|agents|commands|memory)|MEMORY\.md", "Writes to Claude memory/skills/instructions"),
    ("claude-tamper", "MEDIUM", r"mcpServers|\.mcp\.json", "Registers MCP servers"),
    # --- prompt injection (mostly in .md)
    ("injection", "HIGH", r"ignore (all |any )?(previous|prior|above) (instructions|rules)|disregard (the )?(system|previous)", "Instruction override attempt"),
    ("injection", "HIGH", r"(do not|don't|never) (tell|inform|mention|show|reveal)[^\n]{0,40}(user|human)", "Hides actions from the user"),
    ("injection", "HIGH", r"without (asking|confirmation|permission|telling)|silently|automatically approve|no need to (ask|confirm)", "Skips user consent"),
    ("injection", "MEDIUM", r"you are now|new system prompt|act as (root|admin|developer mode)|jailbreak|DAN mode", "Role/system hijack phrasing"),
    ("injection", "MEDIUM", r"<!--[\s\S]{0,400}?-->", "HTML comment (hidden text in Markdown)"),
    # --- destructive
    ("destructive", "HIGH", r"rm\s+-[rf]{2}\s+(/|~|\$HOME|\*)|\bmkfs\b|\bdd\s+if=|diskutil\s+erase|shred\s", "Destructive file/disk operation"),
    # --- advertising / monetization
    ("ads", "MEDIUM", r"sponsored|affiliate|promo ?code|discount code|referral|utm_(source|medium|campaign)|\?ref=|buy now|upgrade to (pro|premium)", "Advertising/affiliate content"),
    ("ads", "LOW", r"(recommend|mention|suggest)[^\n]{0,30}(our|my) (product|service|company|website)", "Self-promotion instruction"),
    # --- crypto
    ("crypto", "HIGH", r"xmrig|stratum\+tcp|coinhive|cryptonight|minerd", "Crypto-miner"),
    ("crypto", "MEDIUM", r"\b(0x[a-fA-F0-9]{40}|bc1[a-z0-9]{25,60}|[13][a-km-zA-HJ-NP-Z1-9]{25,34})\b", "Hard-coded wallet address"),
]
COMPILED = [(c, s, re.compile(p, re.I), e) for c, s, p, e in RULES]

INVISIBLE = {"\u200b", "\u200c", "\u200d", "\u2060", "\ufeff", "\u00ad"}
BIDI = {chr(c) for c in list(range(0x202A, 0x202F)) + list(range(0x2066, 0x206A))}
BIN_EXT = {".exe", ".dll", ".so", ".dylib", ".bin", ".pyc", ".pyo", ".class", ".jar", ".app", ".pkg", ".dmg", ".msi", ".deb", ".rpm", ".node", ".wasm"}
ARCHIVE_EXT = {".zip", ".tar", ".gz", ".tgz", ".7z", ".rar", ".xz", ".bz2"}
CODE_EXT = {".py", ".js", ".mjs", ".cjs", ".ts", ".sh", ".rb", ".go"}
MD_EXT = {".md", ".mdx"}
TEXT_LIMIT = 2_000_000
URL_RE = re.compile(r"https?://([a-zA-Z0-9.-]+)")
B64_RE = re.compile(r"[A-Za-z0-9+/=]{200,}")
HEX_RE = re.compile(r"(\\x[0-9a-fA-F]{2}){20,}")
CP_CALL = re.compile(r"\.(exec|execSync|spawn)\s*\(")
PINNED = re.compile(r"\b(npx|uvx|bunx)\s+(-y\s+)?(@[\w.-]+/)?[\w.-]+@\d+(\.\d+)*\b(?![\w.-])")
COMMENT_RE = re.compile(r"\s*(#|//|/\*|\*)")
INJECTION_PHRASES = {"injection.instruction-override-attempt", "injection.hides-actions-from-the-user",
                     "injection.skips-user-consent", "injection.role-system-hijack-phrasing"}
DOC_SAFE = {"secrets.mentions-secrets-tokens", "exfil.sends-data-over-http", "rce.dynamic-code-execution",
            "rce.dynamic-import-compile", "rce.runs-shell-commands", "deps.installs-dependencies"}
NEVER_DOWN = {"backdoor", "destructive", "crypto", "claude-tamper"}

# "What you do" per level (CARD-SPEC §1).
ACTION = {
    "CRITICAL": "Do not install. Not even fixed. Block the source.",
    "HIGH": "Don't install as-is. Install only the fixed version.",
    "MEDIUM": "Install after the fix (recommended), or as-is if you accept the explained risk.",
    "LOW": "Safe to install. Fix optional.",
}
# Cheapest rewrite per category: smallest edit that removes the risk and keeps the skill's purpose.
FIX = {
    "rce": "Replace eval/exec/shell calls with a fixed command list or a safe parser (json.loads, ast.literal_eval); pin any npx/uvx package to an exact version.",
    "deps": "Pin every dependency to an exact version; delete install-time scripts.",
    "secrets": "Remove the credential/env read; ask the user to pass only the one value needed.",
    "privacy": "Remove the personal-data read; work only on files the user names.",
    "exfil": "Delete the outbound call, or limit it to one documented domain that receives no user data.",
    "backdoor": "Delete the persistence/privilege step; run only when the user invokes the skill.",
    "claude-tamper": "Remove edits to Claude settings/hooks/memory; tell the user what to change instead.",
    "injection": "Delete the hidden or overriding text; keep only plain task steps.",
    "destructive": "Scope the delete to the skill's own temp folder and ask before running it.",
    "ads": "Strip promo/affiliate/tracking text and links.",
    "crypto": "Remove the miner or wallet address.",
    "binary": "Replace the binary/archive with readable source, or drop it.",
    "obfuscation": "Replace the encoded blob/minified code with readable source.",
    "filesystem": "Remove the symlink/hidden file or explain why it's needed.",
}

# --- Cost model (CARD-SPEC §9). Duplicated in scan.py and card.py on purpose; keep both in sync.
SIZES = [(5_000, "Very Small"), (20_000, "Small"), (60_000, "Medium"), (150_000, "Large"), (float("inf"), "Very Large")]
TIER_TOK = {"Script (free)": 0, "Very Small": 200, "Small": 500}
TIER_RANK = {"Script (free)": 0, "Very Small": 1, "Small": 2, "Rewrite": 3}
AUDIT_OVERHEAD, FIX_OVERHEAD = 3000, 1000
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
    """lines: {(file, line): {"sev": SEV, "rids": [rule_id, ...]}}. Returns (tokens, kind in none|fix|rebuild)."""
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


def legend(cost):
    p = lambda d: (" " + fmt_usd(d)) if d is not None else ""
    s = f"🔍 audit {_k(cost['audit_tokens'])} {cost['audit_size']}{p(cost['audit_usd'])}"
    if cost["fix_tokens"]:
        s += f" · {'🧱 rebuild' if cost['fix_kind'] == 'rebuild' else '🔧 fix'} {_k(cost['fix_tokens'])} {cost['fix_size']}{p(cost['fix_usd'])}"
    else:
        s += " · fix: none needed"
    return s


# --- findings
def rule_id(cat, msg):
    head = re.split(r"\s*(?:\(|:|—|->)", msg)[0]
    return cat + "." + re.sub(r"[^a-z0-9]+", "-", head.lower()).strip("-")


def add(findings, sev, cat, path, line, msg, snippet=""):
    findings.append({"severity": sev, "category": cat, "file": path, "line": line, "issue": msg,
                     "snippet": snippet[:160], "rule_id": rule_id(cat, msg), "confidence": "likely"})


def downgrade(f, reason, to=None):
    f["downgraded_from"], f["reason"], f["confidence"] = f["severity"], reason, "suspected"
    f["severity"] = to or LOWER[f["severity"]]


def context_pass(fs, ext, line, in_fence, in_front):
    """Context downgrades (CARD-SPEC §10). fs: findings of this line, in place."""
    for f in fs:
        rid, sev = f["rule_id"], f["severity"]
        if sev == "CRITICAL" or f["category"] in NEVER_DOWN or in_front:
            continue
        if rid == "exfil.raw-network-socket-reverse-shell-pattern" and "AF_UNIX" in line and "/dev/tcp" not in line:
            downgrade(f, "AF_UNIX socket (local only)", "LOW")
        elif rid in INJECTION_PHRASES and ext in CODE_EXT and COMMENT_RE.match(line):
            downgrade(f, "injection phrase in a code comment", "LOW")
        elif in_fence and rid in DOC_SAFE and sev != "LOW":
            downgrade(f, "inside a Markdown code block (documentation)", "LOW")
        elif rid == "rce.runs-a-package-fetched-at-runtime" and PINNED.search(line) and "@latest" not in line:
            downgrade(f, "package pinned to an exact version", "LOW")


def scan_text(text, rel, findings, domains):
    ext = os.path.splitext(rel)[1].lower()
    lines = text.splitlines()
    if lines and max(len(l) for l in lines) > 1000 and ext in CODE_EXT | {".ts"}:
        add(findings, "HIGH", "obfuscation", rel, 0, "Minified/very long line in source — possible obfuscation")
    has_cp = "child_process" in text
    in_fence, in_front = False, bool(lines) and lines[0].strip() == "---" and os.path.basename(rel) == "SKILL.md"
    for i, line in enumerate(lines, 1):
        if i > 1 and in_front and line.strip() == "---":
            in_front = False
            continue
        if ext in MD_EXT and re.match(r"\s*(```|~~~)", line):
            in_fence = not in_fence
            continue
        fs = []
        for cat, sev, rx, expl in COMPILED:
            if expl.startswith("HTML comment") and ext not in MD_EXT | {".txt"}:
                continue
            if rx.search(line):
                add(fs, sev, cat, rel, i, expl, line.strip())
        if has_cp and CP_CALL.search(line) and not any(f["rule_id"] == "rce.runs-shell-commands" for f in fs):
            add(fs, "MEDIUM", "rce", rel, i, "Runs shell commands", line.strip())
        for m in URL_RE.finditer(line):
            domains[m.group(1).lower()] += 1
        if B64_RE.search(line):
            add(fs, "HIGH", "obfuscation", rel, i, "Long base64-like blob (hidden payload?)", line.strip())
        if HEX_RE.search(line):
            add(fs, "HIGH", "obfuscation", rel, i, "Hex-escaped string (hidden payload?)", line.strip())
        chk = line[1:] if i == 1 and line.startswith("\ufeff") else line  # a BOM at file start is fine
        bad = [c for c in chk if c in INVISIBLE or c in BIDI or 0xE0000 <= ord(c) <= 0xE007F]
        if bad:
            names = sorted({unicodedata.name(c, hex(ord(c))) for c in bad})
            add(fs, "CRITICAL" if any(c in BIDI or ord(c) >= 0xE0000 for c in bad) else "HIGH",
                "injection", rel, i, "Invisible/bidi/tag unicode (hidden instructions): " + ", ".join(names), repr(line.strip())[:160])
        context_pass(fs, ext, line, in_fence and ext in MD_EXT, in_front)
        findings.extend(fs)
    if ext in MD_EXT | {".txt"}:  # multiline HTML comments
        for m in re.finditer(r"<!--([\s\S]*?)-->", text):
            if m.group(1).strip():
                add(findings, "MEDIUM", "injection", rel, text.count("\n", 0, m.start()) + 1, "Hidden HTML comment — read it", m.group(1).strip()[:160])


def scan_file(full, rel, findings, domains, root):
    st = os.lstat(full)
    if stat.S_ISLNK(st.st_mode):
        target = os.path.realpath(full)
        sev = "HIGH" if not target.startswith(os.path.realpath(root)) else "LOW"
        add(findings, sev, "filesystem", rel, 0, f"Symlink -> {target}")
        return None
    ext = os.path.splitext(full)[1].lower()
    if st.st_mode & stat.S_IXUSR:
        add(findings, "LOW", "filesystem", rel, 0, "File is executable")
    if ext in BIN_EXT:
        add(findings, "HIGH", "binary", rel, 0, f"Compiled/binary file ({ext}) — cannot be reviewed as source")
        return None
    if ext in ARCHIVE_EXT:
        add(findings, "HIGH", "binary", rel, 0, f"Nested archive ({ext}) — contents hidden from review")
        return None
    if st.st_size > TEXT_LIMIT:
        add(findings, "MEDIUM", "filesystem", rel, 0, f"Very large file ({st.st_size} bytes)")
        return None
    with open(full, "rb") as fh:
        raw = fh.read()
    if b"\x00" in raw[:8000]:
        add(findings, "HIGH", "binary", rel, 0, "Binary content (null bytes) in non-binary extension")
        return None
    text = raw.decode("utf-8", errors="replace")
    scan_text(text, rel, findings, domains)
    return text


def excluded(rel, excl):
    rel = rel.replace(os.sep, "/")
    return any(rel == e or rel.startswith(e + "/") for e in excl)


def load_bundle(src, want):
    """-> {relpath: text} decoded in memory only. want=None: every set, names prefixed '<set>/'."""
    try:
        data = json.load(sys.stdin if src == "-" else open(src, encoding="utf-8"))
        sets = data["sets"]
    except (OSError, ValueError, KeyError, TypeError) as e:
        print(f"scan.py: bad bundle {src}: {e}", file=sys.stderr); sys.exit(64)
    if want is not None and want not in sets:
        print(f"scan.py: no set {want!r} in bundle (sets: {', '.join(sorted(sets))})", file=sys.stderr); sys.exit(64)
    out = {}
    for name, blob in sorted(sets.items()):
        if want not in (None, name):
            continue
        files = json.loads(zlib.decompress(base64.b64decode(blob)).decode("utf-8"))
        for rel, t in files.items():
            out[rel if want else f"{name}/{rel}"] = t
    return out


def main():
    argv = sys.argv[1:]
    opts = [a for a in argv if a.startswith("--")]
    pos = [a for a in argv if not a.startswith("--")]
    if not pos:
        print(__doc__); sys.exit(64)
    as_json, color, is_bundle = "--json" in opts, "--color" in opts, "--bundle" in opts
    excl = [a.split("=", 1)[1].strip("/") for a in opts if a.startswith("--exclude=")]
    want = next((a.split("=", 1)[1] for a in opts if a.startswith("--set=")), None)
    findings, domains, inventory = [], Counter(), []
    file_chars, hashes = {}, {}
    if is_bundle:
        if "--mark-clean" in opts:
            print("scan.py: --mark-clean is refused on bundles (test samples are never marked clean)", file=sys.stderr); sys.exit(64)
        target = "bundle:" + (pos[0] if pos[0] == "-" else os.path.abspath(pos[0])) + (f"#{want}" if want else "")
        for rel, text in sorted(load_bundle(pos[0], want).items()):
            if excluded(rel, excl):
                continue
            inventory.append(rel)
            file_chars[rel] = min(len(text), TEXT_LIMIT)
            scan_text(text, rel, findings, domains)
    else:
        root = os.path.abspath(pos[0]); target = root
        paths = [(root, os.path.basename(root))] if os.path.isfile(root) else []
        if os.path.isdir(root):
            for d, dirs, files in os.walk(root, followlinks=False):
                reld = os.path.relpath(d, root)
                dirs[:] = sorted(x for x in dirs if x not in {".git", "node_modules", "__pycache__"}
                                 and not excluded(os.path.normpath(os.path.join(reld, x)), excl))
                if "node_modules" in os.listdir(d):
                    add(findings, "MEDIUM", "deps", reld, 0, "Vendored node_modules — large unreviewable surface")
                for f in sorted(files):
                    rel = os.path.normpath(os.path.join(reld, f))
                    if not excluded(rel, excl):
                        paths.append((os.path.join(d, f), rel))
                for x in dirs:
                    if x.startswith(".") and x not in {".claude-plugin", ".github"}:
                        add(findings, "LOW", "filesystem", os.path.normpath(os.path.join(reld, x)), 0, "Hidden directory")
        for full, rel in paths:
            inventory.append(rel)
            if os.path.basename(rel).startswith(".") and os.path.basename(rel) not in {".gitignore", ".mcp.json"}:
                add(findings, "LOW", "filesystem", rel, 0, "Hidden file")
            try:
                text = scan_file(full, rel, findings, domains, root)
                if text is not None:
                    file_chars[rel] = len(text)
                if not os.path.islink(full):
                    with open(full, "rb") as fh:
                        hashes[rel] = hashlib.sha256(fh.read()).hexdigest()
            except OSError as e:
                add(findings, "MEDIUM", "filesystem", rel, 0, f"Unreadable: {e}")
    findings.sort(key=lambda f: (-SEV_ORDER[f["severity"]], f["file"], f["line"]))
    counts = Counter(f["severity"] for f in findings)
    # --- hash cache: files byte-identical to a reviewed-clean version need no manual re-read
    cache_path = os.path.join(_BASE, "audit-cache.json")
    cache = _jload("audit-cache.json")
    unchanged = sorted(r for r, h in hashes.items() if h in cache)
    if "--mark-clean" in opts:  # call only after a human-approved review
        import datetime
        for r, h in hashes.items(): cache[h] = {"file": r, "date": datetime.date.today().isoformat()}
        with open(cache_path, "w", encoding="utf-8") as fh:
            json.dump(cache, fh, indent=0)
    # --- cost (CARD-SPEC §9)
    lib, prices, cal = _jload("explanations.json"), _jload("prices.json"), _jload("calibration.json")
    merged = {}  # one entry per file:line, highest severity wins
    for f in findings:
        m = merged.setdefault((f["file"], f["line"]), {"sev": f["severity"], "rids": [], "tags": [], "cats": [], "snip": f["snippet"]})
        if SEV_ORDER[f["severity"]] > SEV_ORDER[m["sev"]]: m["sev"] = f["severity"]
        if f["rule_id"] not in m["rids"]: m["rids"].append(f["rule_id"])
        tag = f"{f['category']}:{f['issue']}" + (" (suspected)" if f["confidence"] == "suspected" else "")
        if tag not in m["tags"]: m["tags"].append(tag)
        if f["category"] not in m["cats"]: m["cats"].append(f["category"])
    read_chars = sum(c for r, c in file_chars.items() if r not in set(unchanged))
    text_chars = sum(file_chars.values())
    audit_t = round((AUDIT_OVERHEAD + read_chars // 4 + 40 * len(merged)) * cal.get("audit", 1.0))
    fix_t, fix_kind = fix_estimate(merged, lib, file_chars, text_chars, cal.get("fix", 1.0))
    cost = {"audit_tokens": audit_t, "audit_size": size_label(audit_t), "fix_tokens": fix_t,
            "fix_size": size_label(fix_t) if fix_t else "None", "fix_kind": fix_kind,
            "audit_usd": usd(audit_t, "opus", 0.9, prices), "fix_usd": usd(fix_t, "sonnet", 0.6, prices),
            "text_chars": text_chars, "file_chars": file_chars}
    present = [s for s in ("CRITICAL", "HIGH", "MEDIUM", "LOW") if counts.get(s)]
    fix_cats = []  # categories needing a fix (MEDIUM+), worst first
    for m in sorted(merged.values(), key=lambda m: -SEV_ORDER[m["sev"]]):
        if SEV_ORDER[m["sev"]] >= 2:
            for c in m["cats"]:
                if c not in fix_cats and c in FIX: fix_cats.append(c)
    result = {"target": target, "files": inventory, "excluded": excl, "domains": dict(domains.most_common()),
              "counts": dict(counts), "cost": cost, "verdicts": {s: ACTION[s] for s in present},
              "cheapest_rewrite": [{"category": c, "fix": FIX[c]} for c in fix_cats],
              "findings": findings, "unchanged_reviewed": unchanged}

    def summary():
        print("Cost: " + cost_bar(audit_t, fix_t, fix_kind, color) + "  " + legend(cost))
        print("What to do:" + ("".join(f"\n  {s.title()}: {ACTION[s]}" for s in present) or " No findings. OK to install after manual review."))
        if fix_cats:
            print("Cheapest rewrite (keeps the skill's purpose; apply only on the user's yes):")
            for c in fix_cats: print(f"  - {c}: {FIX[c]}")

    if as_json:
        print(json.dumps(result, separators=(",", ":")))
    elif "--full" not in opts:
        # Compact (default): same findings, merged per file:line, one snippet, no repetition
        print(f"Files({len(inventory)}): " + ", ".join(inventory))
        if excl: print("Excluded: " + ", ".join(excl))
        if unchanged: print(f"Unchanged since reviewed-clean ({len(unchanged)}, skip manual re-read unless flagged): " + ", ".join(unchanged))
        print("Domains: " + (", ".join(f"{d}({n})" for d, n in domains.most_common()) or "none"))
        print("Counts: " + " ".join(f"{k[0]}={counts.get(k, 0)}" for k in SEV_ORDER if k != "INFO"))
        summary()
        grouped = {}  # MEDIUM/LOW repeats: one line per (file, tags) with all line numbers
        for (fp, ln), m in sorted(merged.items(), key=lambda kv: (-SEV_ORDER[kv[1]["sev"]], kv[0])):
            if SEV_ORDER[m["sev"]] >= 3:
                snip = f" | {m['snip'][:100]}" if m["snip"] else ""
                print(f"{m['sev'][0]} {fp}:{ln} {'; '.join(m['tags'])}{snip}")
            else:
                g = grouped.setdefault((m["sev"], fp, "; ".join(m["tags"])), {"lines": [], "snip": m["snip"]})
                g["lines"].append(ln)
        for (sev, fp, tags), g in grouped.items():
            snip = f" | e.g. {g['snip'][:80]}" if g["snip"] else ""
            print(f"{sev[0]} {fp}:{','.join(map(str, g['lines']))} {tags}{snip}")
    else:
        print(f"Target: {target}\nFiles ({len(inventory)}):"); [print("  -", p) for p in inventory]
        if excl: print("Excluded:", ", ".join(excl))
        print("\nExternal domains referenced:"); [print(f"  - {d} ({n})") for d, n in domains.most_common()] or print("  (none)")
        print("\nCounts:", {k: counts.get(k, 0) for k in SEV_ORDER}); summary()
        for f in findings:
            if f["severity"] == "INFO": continue
            dg = f" (suspected, was {f['downgraded_from']}: {f['reason']})" if "downgraded_from" in f else ""
            print(f"[{f['severity']}] {f['rule_id']} {f['file']}:{f['line']} — {f['issue']}{dg}")
            if f["snippet"]: print(f"      {f['snippet']}")
    sys.exit(2 if counts.get("CRITICAL") else 1 if counts.get("HIGH") else 0)


if __name__ == "__main__":
    main()
