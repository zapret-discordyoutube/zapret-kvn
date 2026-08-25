---
name: zapret-kvn-release
description: Build, verify, package, publish, resume, or deliver Zapret KVN Windows x64 stable releases with the repository one-command runner, local Windows dev/stable gates, immutable Forgejo assets, and stable-only Telegram delivery through ZapretGPT. Use for release, build, version bump, stable publication, release assets, Telegram channel delivery, or recovery of an interrupted Windows release in /home/codex-pve/Xray-windows-64.
---

# Release Zapret KVN Windows stable

## Use the deterministic runner

Work on `main`. Finish and commit intentional product changes, preserve unrelated
user changes, and require a clean tree before starting. Write 1–6 short
user-facing changelog items from the complete previous stable tag → current
source range.

Run one command from the repository root:

```bash
python3 scripts/release_windows.py \
  --change "First stable change" \
  --change "Second stable change"
```

The version defaults to the next patch after the latest stable tag. Pass
`--version MAJOR.MINOR.PATCH` to make that same next patch explicit or, when the
user explicitly requests a minor release, the immediate next minor `.0`.
Telegram delivery is included by default; use `--no-telegram` only when the user
explicitly excludes channel delivery.

For a non-mutating environment check, run the same command with `--preflight`.
This does not replace the real run.

## Trust the runner contract

The runner owns the full release transaction:

- validate clean `main`, next-patch version and changelog limits;
- update `APP_VERSION`, create the single release-source commit and push it;
- pin the cached Windows workspace to that exact SHA;
- run separate dev and stable gates with pinned cores, dependencies, all Windows
  tests, `python build.py --no-zip`, and shipped-template verification;
- package and test the five Windows assets and verify copied SHA-256 values;
- create the immutable tag, draft Forgejo Release, upload exactly five assets,
  download and hash them again, publish and verify Latest;
- sync the verified installer and invoke the already-running ZapretGPT through
  its owner-only Unix socket, then confirm publisher state;
- fetch final Git state and require a clean worktree.

Do not manually repeat successful runner checks. Report the runner's final JSON,
test totals, exact SHA, Release URL, asset count, and Telegram result.

## Resume failures

The runner stores its phase under `.git/zapret-kvn-release-state.json`. After a
network, Windows, Forgejo, or Telegram failure, fix only the diagnosed external
condition and rerun the same command. It resumes the first incomplete phase and
verifies already-created immutable objects instead of rebuilding or reposting
them.

Never delete the state file to bypass a failure. Never overwrite an existing tag
or Release asset; publish a correction under the next patch. Use manual commands
only when the runner itself is proven defective, fix the runner, test it, and
resume through it.

## Preserve safety boundaries

- Use the trusted `win10` workspace; Forgejo Actions remain source validation.
- Never smoke-start the GUI or call PyInstaller directly.
- Never publish dev, test, RC, draft, or prerelease files to stable or Telegram.
- Never print or put Forgejo/Telegram credentials in argv, logs, Git, or Windows.
- Never start a second bot or Pyrogram client. Telegram publication must use
  `/home/codex-pve/zapretgpt/data/zapretgpt-admin.sock`.
- Keep generated assets and release state outside tracked source.
