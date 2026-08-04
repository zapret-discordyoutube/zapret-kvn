---
name: zapret-kvn-release
description: Build, package, verify, and publish Zapret KVN stable Windows x64 releases locally. Use when working in /home/codex-pve/Xray-windows-64 and the user asks to build locally, publish or release a stable version, replace release assets, bump the application version, or prepare the five Windows release artifacts. Keep GitHub Actions as an untouched background fallback.
---

# Zapret KVN Local Release

## Preserve the release contract

- Work directly on `main`; do not create a branch unless the user explicitly asks.
- Treat a request to publish a stable release as authorization to build and package it locally.
- Use the local Windows workstation available through SSH alias `win10`. The Linux host cannot produce the Windows executable directly.
- Keep the `Build & Release` GitHub Actions workflow enabled as a background fallback. Do not inspect, poll, wait for, or cancel its runs unless the user explicitly changes this rule.
- Do not smoke-start the built GUI.
- Use `python build.py` for the application build. Never invoke PyInstaller directly.

## Prepare the exact release source

1. Read `AGENTS.md`, inspect the worktree, and preserve unrelated user changes.
2. Validate source changes with relevant tests and `git diff --check` before committing or pushing.
3. Push the intended release commit to `main` and record its full SHA.
4. Determine the next stable patch version from the latest stable Git tag. Do not infer completion from `APP_VERSION` alone because the background workflow may bump it later.
5. Build from that exact commit in a dedicated Windows workspace such as `C:\Users\privacy\ZapretKVN-local-release`. Keep the workspace and caches for future releases; never delete an unverified directory.
6. If the exact commit still contains the previous `APP_VERSION`, update only the disposable Windows build copy to the new version before building. Synchronize the tracked version on `main` after publication if the background workflow has not already done so.

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

- If the stable GitHub Release does not exist, create it for the exact release commit with generated notes and mark it latest.
- If the background workflow already created the release, leave the workflow untouched and replace all five assets with the locally built files using `gh release upload --clobber`.
- Read back the release and verify that it is published, non-prerelease, latest, and contains all five expected assets with nonzero sizes.
- Fetch `origin/main` and tags after publication. Fast-forward local `main`; if the tracked `APP_VERSION` still needs updating, commit it with `[skip ci]` and push.
- Keep GitHub Actions as fallback even after a successful local publication; do not report or wait on its status.
