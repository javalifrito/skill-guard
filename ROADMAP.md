# Roadmap: v2 (decided 2026-11-08)

Status: decided, not built. Build order follows the model plan at the bottom.

## 1. Danger levels (every level says what to do)
| Level | Meaning | What you do |
|---|---|---|
| 🔴 Critical | Built to harm or steal | **Do not install.** Not even fixed. Block the source. |
| 🟠 High | Could seriously expose data/computer | **Don't install as-is.** Install only the fixed version. |
| 🟡 Medium | Risky habit, not an attack (telemetry, unpinned updates) | **Install after the fix** (recommended), or as-is if you accept the explained risk. |
| 🔵 Low | Untidy but harmless | **Safe to install.** Fix optional. |
| ⚪ Info | Just so you know | **Safe to install.** Nothing to do. |

The card's top line takes the worst level found, e.g. "🟠 Install only the fixed version · Fix cost: Small".

## 2. Cost estimate (audit + fix)
- Pre-audit estimate by script (free): file sizes + skill overhead + report.
- Fix estimate per finding type: mechanical fixes done by the script ≈ 0 tokens; small edits = a few hundred tokens; rewrite ≈ 2× file size.
- Tiers: Very Small <5k · Small 5–20k · Medium 20–60k · Large 60–150k (ask first) · Very Large >150k (ask first).
- Dollar estimate per model (Opus for review, Sonnet for fix). Get prices from the claude-api skill at build time.
- Log estimate vs. actual for each audit and use it to recalibrate (backtest).

## 3. Cost bar
- Green→red gradient with a marker for the audit cost and one for the fix cost.
- Claude Desktop/web: visual card. Terminal/other platforms: emoji bar `🟩🟩🟨🟧⬜ Small · ~12k tokens`.
- Rendered by a script from the scan JSON: 0 LLM tokens.

## 4. Problems card (for non-programmers), shown after every audit
- Categories: Passwords & accounts · Your private files · Takes over your computer · Sends your data elsewhere · Hidden tricks (manipulating Claude) · Ads & tracking · Unsafe code · Cost.
- Each problem: what it is, a real-life comparison, the fix, and the fix's cost tier.
- Plain-language explanations come from a fixed library (one per scanner rule): 0 tokens and consistent. The LLM writes only for unusual findings.

## 5. Fix mode
- Fixable issues (telemetry, pinning, ads, broad permissions, missing confirmations, hidden text) → small patches, not a full regeneration.
- Malicious intent (exfiltration, backdoor, hidden instructions) → never patch the author's code. Write a fresh version from the stated purpose.
- A script does the mechanical fixes. The LLM only does changes that need judgment. Shrink while fixing (short description, references loaded only on use).
- Prove it: re-scan (0 Critical/High) + sample prompts compared against the original.
- Save as `<name>-safe` with the original source and SHA recorded, auto-update off, upstream changes reviewed by diff.

## 6. Other improvements
1. Enforcement hook: block `npx skills add`, `claude plugin install` etc. unless audit-log has an approval for that exact SHA.
2. Fewer false positives: downgrade matches inside Markdown code examples (backtest: 0 findings lost).
3. Dependency CVE check via osv.dev.
4. Re-audit installed skills once (find-skills uses `-y` auto-confirm), then a weekly check of upstream changes.
5. Optional sandbox run (no network) for "conditions" verdicts.
6. Confidence per finding (confirmed / suspected).

## 7. Sharing & platforms
- Public GitHub repo **`skill-guard`**, packaged as a Claude Code plugin (marketplace), plus a claude.ai skill zip.
- No personal data in the repo (audit-log, cache, paths); CLAUDE.md rule as a copy-paste snippet in the README.
- The repo audits itself: the card goes in the README; tagged releases so users can pin a version.
- **Claude first.** For other platforms, ship `PORTING.md`: the other model reads it and translates the skill itself (the porting cost is paid on that platform). It must include:
  - A "must keep" checklist (levels, never run the skill's code, install only on a yes).
  - A self-test: scan `examples/` malicious sample → must show 🔴.
  - Honest limits (no GitHub check without network, no hooks).
- Each skill repo gets a vault folder here with files + an index note (repo URL, version, platforms, verdict, install command).

## 8. GitHub publishing (blocker)
- The GitHub connector fails: it needs a personal access token stored in a config file as plain text, which the audit itself rates 🟠. Not used.
- No Homebrew (Intel Mac, Terminal available). Options:
  - **GitHub Desktop** (GUI sign-in, token kept in Keychain; user clicks Publish/Push), or
  - **`gh` CLI via the official macOS .pkg** from cli.github.com, then `gh auth login` (browser sign-in). This lets Claude push without clicks.
- Pick one before step "publish".

## Model plan
| Part | Model |
|---|---|
| Card design, fix-mode logic, PORTING.md | Opus |
| Cost estimator, card/bar generator, explanation library, hook, packaging | Sonnet |
| Repo creation, vault notes, backtests, docs | Haiku |
