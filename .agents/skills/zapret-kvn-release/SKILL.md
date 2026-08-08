---
name: zapret-kvn-release
description: Build, verify, package, and publish Zapret KVN Windows x64 releases locally with a default dev-then-stable sequence, Forgejo publication, and stable-only Telegram delivery through ZapretGPT to @vpndiscordyooutube. Use when working in /home/codex-pve/Xray-windows-64 and the user asks to build locally, publish or release a version, replace release assets, bump the application version, prepare the five Windows release artifacts, or deliver the Windows installer to the channel. Forgejo Actions is portable source validation only. Never publish dev, test, RC, draft, or prerelease builds to the stable Release or Telegram channel.
---

# Zapret KVN Local Release

A commit is a readiness boundary. Never create an intermediate, checkpoint, or
partially verified commit. During a stable release, inspect the entire shared
working tree, finish and validate every intentional source change, and include
every ready change regardless of who authored it. If an intentional source
change is incomplete or unsafe, stop the stable release until it is resolved
instead of hiding, stashing, or excluding it. Generated packages, caches,
credentials, and other local-only build state are never part of this source
scope.

## Preserve the release contract

- Work directly on `main`; do not create a branch unless the user explicitly asks.
- Treat a request to publish a stable release as authorization to build and package it locally.
- Use the local Windows workstation available through SSH alias `win10`. The Linux host cannot produce the Windows executable directly.
- Treat Forgejo Actions as independent portable source validation and keep its
  source-verification workflow enabled. The trusted Windows workstation remains
  the only stable Windows build owner because the Forgejo runner is Linux-only.
- Use `dev -> stable` as the default release sequence. A normal stable release
  request authorizes both stages. Stop after dev only when the user explicitly
  requests a dev-only build.
- Treat dev as a validation gate: build and test the candidate commit locally,
  but do not create a stable tag, Forgejo Release, release assets, or Telegram
  post from it.
- Choose and set the stable version before the one final release-source commit.
  After the dev gate passes, rebuild stable from that same exact SHA. Never make
  a checkpoint dev commit, create a second version-only commit, rename, promote,
  or reuse dev binaries as stable assets.
- Do not smoke-start the built GUI.
- Use `python build.py` for the application build. Never invoke PyInstaller directly.
- Treat a source commit or push as source delivery only. Never use it as a
  Telegram publication signal; channel delivery is reserved for a completed
  stable release.

## Prepare the exact release source

1. Read `AGENTS.md` and inspect every tracked and untracked path. For stable,
   treat every intentional source change in the shared tree as release scope
   regardless of author. Finish and validate it or stop before publication.
2. Determine the next stable patch version from the latest stable Git tag; do
   not infer it from `APP_VERSION`. Set the intended stable `APP_VERSION` in the
   shared checkout; do not use a private Windows-only version edit.
3. Validate the complete final source snapshot with relevant tests and
   `git diff --check`. Stage every reviewed, ready source change by explicit
   path, excluding generated packages, caches, credentials, and local-only
   files, then review the exact staged diff.
4. Create one concise release-source commit only after the complete source task
   and all required checks have succeeded. Push it to `main`, record its full
   SHA, and run the Windows dev gate from that exact commit.
5. Continue only after the dev gate passes. Do not create another source or
   version commit between the dev gate and stable rebuild.
6. Build stable from the same exact commit in a dedicated Windows workspace such as
   `C:\Users\privacy\ZapretKVN-local-release`. Keep the workspace and caches for
   future releases; never delete an unverified directory.

## Use the cached fast path

- Reuse the existing Windows workspace instead of cloning again. Restore only known disposable build-copy edits, fetch `origin`, and detach at the exact release SHA.
- Reuse `.venv`; still run `pip install -r requirements.txt` and `pip check` so dependency changes are applied.
- Reuse the download cache under `.cache` and the PyInstaller cache under the Windows user profile.
- Reuse `.cache/core-bundle/core-windows-x64.7z` only when the installed `core/core-manifest.windows-x64.json` `lock_sha256` equals the SHA-256 of `scripts/core-lock.windows-x64.json`. Otherwise rebuild the bundle. Always run the install/verification step before tests.
- Remove only exact, version-named output archives before repackaging. Do not broadly clean the workspace or caches.

## Run the dev gate on Windows

1. Fetch the pushed release candidate and detach the cached workspace at its exact
   SHA. Preserve unrelated untracked helper files.
2. Check whether `ZapretKVN.exe` is running. Stop only the verified application process and its verified bundled core processes when they would lock build files or test ports.
3. Build and install the pinned core bundle:

   ```powershell
   ./scripts/build_core_bundle.ps1
   ./scripts/install_core_bundle.ps1
   ```

4. Create or reuse `.venv`, install `requirements.txt`, and run `pip check`.
5. Run the full Windows test suite:

   ```powershell
   .venv/Scripts/python.exe -m unittest discover -s tests -v
   ```

6. Run the project builder without starting the application:

   ```powershell
   python build.py --no-zip
   ```

7. Verify the dev EXE exists and contains the expected shipped templates. Do
   not package, tag, publish, or send this dev build.

## Rebuild stable on Windows

1. After the dev gate passes on the final release-source commit, fetch `origin`
   and detach the same cached workspace at that exact SHA.
2. Require the tracked `APP_VERSION` to equal the intended stable version and
   require the stable tag and Forgejo Release to be absent.
3. Reinstall/verify the pinned core bundle, update `.venv` dependencies, run
   `pip check`, and rerun the full Windows test suite.
4. Run `python build.py --no-zip` again. This fresh output, not the dev output,
   is the only input allowed for stable packaging. Do not smoke-start the GUI.

## Package and verify

Use Windows 7-Zip to create the same five assets as the release workflow:

- `ZapretKVN-v<VERSION>-windows-x64.exe` — 7z SFX from `dist/ZapretKVN`;
- `ZapretKVN-v<VERSION>-windows-x64.zip` — updater archive;
- `ZapretKVN-v<VERSION>-windows-x64.zip.sha256` — lowercase raw SHA-256 plus newline;
- `ZapretKVN-v<VERSION>-windows-x64.7z` — ordinary 7z archive;
- `ZapretKVN-cores-v<VERSION>-windows-x64.7z` — verified `.cache/core-bundle/core-windows-x64.7z`.

Run `7z t` on the SFX, ZIP, 7z, and core bundle. Recompute the ZIP hash after transferring the files back to the Linux host and require it to match the `.sha256` file.

## Publish locally built assets

- Before publishing, review the complete range from the previous exact stable
  tag through the new stable tag, including every intervening dev, test, and RC
  change. Write 1–6 short user-facing changelog items from the actual diff and
  verified behavior. The working agent must write them; do not delegate this
  text to Gemini or the Telegram bot.
- Read the Forgejo token from a mode-`0600` file outside Git. Never print it,
  place it in a command-line URL, copy it into the Windows build, or commit it.
- Require an absent immutable `v<VERSION>` tag and Forgejo Release. Push the
  tag to the exact verified source commit, create a draft release, and upload
  exactly the five verified assets.
- Never delete, replace, or overwrite an existing Forgejo asset. If an existing
  asset differs, stop and publish the correction under a new tag.
- Publish the draft only after every remote asset has the expected nonzero
  size. Download every asset back over HTTPS and compare its SHA-256 with the
  qualified local file.
- Read back the release and verify that it is published, non-prerelease,
  selected as Latest, bound to the exact source commit, and contains no extra
  or missing assets.
- Fetch `origin/main` and tags after publication and require the local worktree
  to remain clean. Forgejo Actions must not create, replace, or publish stable
  Windows releases.

## Deliver the installer to Telegram

Keep Telegram delivery stable-only. Accept only the verified installer for an
exact `vMAJOR.MINOR.PATCH` stable release produced by this workflow. Never send
an ordinary development build, test/RC-suffixed version, draft, prerelease, or
an artifact created merely because a commit was pushed.

After packaging and while `win10` is reachable, copy the latest verified local
installer into the host publisher cache:

```bash
/home/codex-pve/zapretgpt/.venv/bin/python \
  /home/codex-pve/zapretgpt/zapretkvn_publisher.py --sync-windows
```

The production `zapretgpt.service` does not scan the VM in the background.
`/zkvn_status` and `/zkvn_publish windows <version>` request synchronization on
demand; the publish command prefers this local VM installer and falls back to
the latest published stable Forgejo installer when the VM is off. It sends only
`ZapretKVN-v<VERSION>-windows-x64.exe` through `@zapretbypass_bot` to
`@vpndiscordyooutube`.

When channel delivery is requested, require posting permission and confirm a
new `published` entry in
`/home/codex-pve/zapretgpt/data/zapretkvn_publisher_state.json` or a successful
publisher log. Put the agent-written stable changelog in the final `changes:`
field, with semicolons between items:

```text
/zkvn_publish windows <version> changes: First stable change; Second stable change
```

Send that command privately to `@zapretbypass_bot` for immediate delivery. Do
not start another bot or Pyrogram client. Put `force` before `changes:` only to
repost the same verified stable installer; it must never bypass the stable-only
rule.
