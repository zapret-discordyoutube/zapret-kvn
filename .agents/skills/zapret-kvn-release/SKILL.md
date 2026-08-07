---
name: zapret-kvn-release
description: Build, package, verify, and publish Zapret KVN stable Windows x64 releases locally to the project Forgejo, including stable-only Telegram delivery through ZapretGPT to @vpndiscordyooutube. Use when working in /home/codex-pve/Xray-windows-64 and the user asks to build locally, publish or release a stable version, replace release assets, bump the application version, prepare the five Windows release artifacts, or deliver the Windows installer to the channel. Forgejo Actions is portable source validation only. Never send dev, test, RC, draft, or prerelease builds to the Telegram channel.
---

# Zapret KVN Local Release

## Preserve the release contract

- Work directly on `main`; do not create a branch unless the user explicitly asks.
- Treat a request to publish a stable release as authorization to build and package it locally.
- Use the local Windows workstation available through SSH alias `win10`. The Linux host cannot produce the Windows executable directly.
- Treat Forgejo Actions as independent portable source validation and keep its
  source-verification workflow enabled. The trusted Windows workstation remains
  the only stable Windows build owner because the Forgejo runner is Linux-only.
- Do not smoke-start the built GUI.
- Use `python build.py` for the application build. Never invoke PyInstaller directly.
- Treat a source commit or push as source delivery only. Never use it as a
  Telegram publication signal; channel delivery is reserved for a completed
  stable release.

## Prepare the exact release source

1. Read `AGENTS.md`, inspect the worktree, and preserve unrelated user changes.
2. Validate source changes with relevant tests and `git diff --check` before committing or pushing.
3. Push the intended release commit to `main` and record its full SHA.
4. Determine the next stable patch version from the latest stable Git tag. Do not infer publication from `APP_VERSION` alone.
5. Build from that exact commit in a dedicated Windows workspace such as `C:\Users\privacy\ZapretKVN-local-release`. Keep the workspace and caches for future releases; never delete an unverified directory.
6. Commit the intended stable `APP_VERSION` before building. The immutable Windows build must use the exact pushed source commit without a private version edit.

## Use the cached fast path

- Reuse the existing Windows workspace instead of cloning again. Restore only known disposable build-copy edits, fetch `origin`, and detach at the exact release SHA.
- Reuse `.venv`; still run `pip install -r requirements.txt` and `pip check` so dependency changes are applied.
- Reuse the download cache under `.cache` and the PyInstaller cache under the Windows user profile.
- Reuse `.cache/core-bundle/core-windows-x64.7z` only when the installed `core/core-manifest.windows-x64.json` `lock_sha256` equals the SHA-256 of `scripts/core-lock.windows-x64.json`. Otherwise rebuild the bundle. Always run the install/verification step before tests.
- Remove only exact, version-named output archives before repackaging. Do not broadly clean the workspace or caches.

## Validate and build on Windows

1. Check whether `ZapretKVN.exe` is running. Stop only the verified application process and its verified bundled core processes when they would lock build files or test ports.
2. Build and install the pinned core bundle:

   ```powershell
   ./scripts/build_core_bundle.ps1
   ./scripts/install_core_bundle.ps1
   ```

3. Create or reuse `.venv`, install `requirements.txt`, and run `pip check`.
4. Run the full Windows test suite:

   ```powershell
   .venv/Scripts/python.exe -m unittest discover -s tests -v
   ```

5. Run the project builder without starting the application:

   ```powershell
   python build.py --no-zip
   ```

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
