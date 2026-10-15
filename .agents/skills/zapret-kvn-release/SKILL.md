---
name: zapret-kvn-release
description: Build, verify, package, publish, resume, or deliver Zapret KVN Windows x64 stable releases with the repository one-command runner, local Windows dev/stable gates, immutable Forgejo assets, and stable-only Telegram delivery through ZapretGPT. Use for release, build, version bump, stable publication, release assets, Telegram channel delivery, or recovery of an interrupted Windows release in /home/codex-pve/zapret-kvn/windows.
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
- fetch final Git state and require a clean worktree;
- after completion, keep only the newest 3 versions (`ZAPRETKVN_RELEASE_KEEP`)
  in `~/releases/zapret-kvn`, the ZapretGPT Windows cache and win10 `dist`;
  pruning is best-effort and never fails a finished release.

Do not manually repeat successful runner checks. Report the runner's final JSON,
test totals, exact SHA, Release URL, asset count, and Telegram result.

## Update store (since 0.8.26)

After the Windows build the runner builds the update store with the shared
update core (`windows/zapret_update`, a byte-for-byte copy of Zapret 2 GUI's
`public_zapretgui/src/zapret_update`, synced by `scripts/sync_update_core.py`)
and uploads only missing files to the Forgejo package
`zapretkvn/generic/zapret-kvn-store`. Programs on 0.8.26+ download changed files
and patches from it first; the zip is the fallback.

- Needs Python 3.14 for `compression.zstd`: `ZAPRET_UPDATE_STORE_PYTHON`, default
  `~/.local/share/uv/python/cpython-3.14.6-linux-x86_64-gnu/bin/python3.14`.
  Missing interpreter stops the release before publication.
- Needs the package-only Forgejo token
  `~/.config/forgejo/zapret-update-store-token` (mode 600, scope
  `write:package`; override `ZAPRET_UPDATE_STORE_TOKEN`). Never print it.
- Cache lives in `~/releases/zapret-kvn/update-store`; patches are made from the
  three previous signed releases.
- bsdiff patches (`builder --bsdiff`, needs `bsdiff4` in that Python) are not
  enabled for KVN: zstd patches of `ZapretKVN.exe` are already ~0.1 MB.
- The app itself is built on Python 3.12, which has no `compression.zstd`; it
  unpacks the store with the `zstandard` package from `requirements.txt`.
  Without it the update plan refuses before downloading and the updater falls
  back to zip ranges (0.8.26 shipped without it, so its store step never worked).

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

## Cancel an unpublished release

When the user cancels a running release, stop the runner and any remaining
gate processes on `win10`, then run:

```bash
python3 scripts/release_windows.py --abandon MAJOR.MINOR.PATCH
```

It refuses once the tag exists locally or on origin, or a Forgejo Release
exists; such a release is finished or corrected under the next patch instead.
On success it archives the state as
`.git/zapret-kvn-release-abandoned-vX.Y.Z.json` and records the version in
`.git/zapret-kvn-release-abandoned.json`. The pushed `release: prepare`
commit stays; the next fresh release follows the cancelled version (e.g.
cancelled 0.7.6 → next 0.7.7). Its changelog must also cover what the
cancelled version would have shipped. Never delete the state file by hand.

## Update the user guides

A release with user-visible changes is not finished until the wiki guides describe it (owner decision 15.10.2026). Before or right after publishing, compare the change list with the guide notes in the wiki vault `/home/codex-pve/Privacy` and update them in the same task: `Zapret/premium.md`, `premium/apps.md` (Windows section), `premium/discord.md` (local proxy port, discord-drover), `premium/v2rayn.md`. Retake screenshots whose screens changed. Follow the `AGENTS.md` section «Пользовательские гайды следуют за приложением» and the procedure in `/home/codex-pve/vpnbot/vpnbot_codex/.claude/skills/vpnbot-maintain-user-guides/SKILL.md`. In the final report, name the guide commit or state that no user-visible behaviour changed.

## Preserve safety boundaries

- Use the trusted `win10` workspace; Forgejo Actions remain source validation.
- Never smoke-start the GUI or call PyInstaller directly.
- Never publish dev, test, RC, draft, or prerelease files to stable or Telegram.
- Never print or put Forgejo/Telegram credentials in argv, logs, Git, or Windows.
- Never start a second bot or Pyrogram client. Telegram publication must use
  `/home/codex-pve/zapretgpt/data/zapretgpt-admin.sock`.
- Keep generated assets and release state outside tracked source.
