# AI Handoff: sing-box Raw Config Editor V1

## Copy-Paste Prompt

Implement V1 of a raw `sing-box.json` editor in this repository.

Important: do exactly this scope and do not expand the product into a form
builder, schema designer, or template system.

### Product goal

Replace the current `Маршруты` page with a dedicated `sing-box` config editor
page.

The user should edit a mostly final raw `sing-box.json` directly inside the
app.

The app should almost not modify that config.

### Critical product decisions

1. V1 is only for `sing-box`.
2. This is an engine-specific page. In the future other cores may get their
   own pages with their own architecture.
3. Delete the `Маршруты` page from the UI navigation for this task.
4. Do not build a template engine.
5. Do not build GUI fields for route rules, DNS, TLS, transports, or outbounds.
6. Do not use `RoutingSettings` to drive `sing-box` anymore.
7. The editor is the source of truth for `sing-box` config.
8. The user edits a fully formed JSON config.
9. The app may only do minimal runtime patching when necessary.
10. The only intended V1 runtime patch for usability is quick node switching:
    if the config contains an outbound with tag `proxy`, the app may replace
    that outbound with the currently selected `Node` converted to a `sing-box`
    outbound before launch.
11. If no outbound tag `proxy` exists, the app should launch the config as-is.
12. The config editor page is not tightly bound to the `Серверы` page, but
    selected nodes must still remain useful for quick switching as described
    above.
13. `Маршруты` must not affect `sing-box` at all after this change.
14. Do not call `sing-box check` in V1.
15. Validation in V1 should stay light:
    - read file
    - parse JSON
    - show JSON parse errors clearly
16. Keep the implementation simple and pragmatic.

### Quick node switching rule

Use this exact convention:

- if the edited config contains an outbound object with `"tag": "proxy"`,
  then right before launching `sing-box`, replace that outbound object with the
  currently selected node converted through the existing sing-box conversion
  path;
- preserve the tag as `proxy`;
- do not rewrite the rest of the config;
- do not merge `RoutingSettings` into the config;
- do not generate route rules from GUI state;
- if the selected node uses an unsupported transport for native sing-box
  conversion, fail with a clear user-visible error instead of silently falling
  back to the old routing builder.

### Storage

Store sing-box editor files under:

- `data/templates/sing-box/`

For V1, one active config file is enough.

Persist in app state only what is needed to reopen that active config, such as:

- active config file name or relative path

### UI requirements

Add a dedicated page for sing-box config editing with:

- large plain text editor for JSON
- open file / save file / save buttons
- new config button if useful
- validate button
- apply button or save-and-apply button
- optional pretty-format button if easy
- status/error area

Do not build advanced schema UI.

### Behavior requirements

- The page edits raw JSON text.
- The page can load and save JSON files from the sing-box config folder.
- Validation only parses JSON and reports syntax errors with useful messages.
- Connecting in sing-box mode should use the saved editor config as the base
  config instead of building config from `RoutingSettings`.
- Before launch, optionally patch only the `proxy` outbound from the selected
  node as described above.
- Write the final runtime config to the existing runtime file path used by the
  app for sing-box launch.
- Keep existing node storage and node selection behavior.
- Keep app-managed behavior minimal.

### Things you must not do

- do not create a placeholder/template DSL
- do not add route-rule form controls
- do not keep old `Маршруты` page visible
- do not silently combine editor JSON with `RoutingSettings`
- do not auto-generate a whole sing-box config from the selected node
- do not add heavy validation via external process execution
- do not rebuild or smoke-start the app automatically

### Acceptance criteria

1. The `Маршруты` page is removed from navigation.
2. There is a dedicated sing-box editor page in the UI.
3. The page loads/saves raw JSON from `data/templates/sing-box/`.
4. JSON syntax errors are shown clearly.
5. In sing-box mode, the app launches from the editor config instead of the old
   routing builder.
6. If outbound tag `proxy` exists and a selected node is available, that one
   outbound is replaced from the selected node before launch.
7. If outbound tag `proxy` does not exist, the config is launched unchanged.
8. `Маршруты` no longer affect sing-box behavior.
9. Unsupported selected-node transports for proxy replacement produce a clear
   error instead of silent fallback.
10. The implementation remains simple and does not introduce a template system.

### Files to read first

- `xray_fluent/ui/main_window.py`
- `xray_fluent/ui/routing_page.py`
- `xray_fluent/application/controller.py`
- `xray_fluent/singbox_config_builder.py`
- `xray_fluent/singbox_manager.py`
- `xray_fluent/profiles/models.py`
- `xray_fluent/profiles/storage.py`
- `xray_fluent/constants.py`
- `docs/sing-box/runtime-config.md`

### Implementation strategy

1. Add storage path support for sing-box config files.
2. Add a small editor page widget for raw JSON editing.
3. Wire it into main navigation and remove the old routing page from visible UI.
4. Add controller methods to:
   - load active sing-box config text
   - save sing-box config text
   - parse/validate JSON
   - build final runtime config from editor JSON plus optional `proxy` outbound
     replacement
5. Change sing-box connect flow to use editor config as base config.
6. Keep the old builder code available only as internal helper for outbound
   conversion or fallback paths unrelated to this feature.
7. Do not do a large cleanup refactor unless required to make the feature work.

### Output expectations

Make the code changes directly.

After implementation, report:

- what changed
- which files were added/modified
- how node-to-proxy replacement works
- what limitations remain in V1

## Final Decisions

These decisions are already made and should not be re-opened:

- `sing-box` only in V1
- separate engine-specific page
- no route forms
- no template engine
- raw JSON editor
- `Маршруты` removed from UI
- `Маршруты` do not influence sing-box anymore
- minimal runtime patching only
- `proxy` outbound replacement from selected node is allowed
- no `sing-box check` in V1

## Clarifying Notes

### Why `proxy` replacement is allowed

The product still needs fast server switching using existing `Node` storage.
The narrowest possible solution is to reserve tag `proxy` as the single
replaceable outbound convention.

This keeps the editor raw and simple while preserving current node utility.

### What "almost does not touch the config" means

It means:

- do not rebuild full config from app state
- do not merge route GUI state
- do not synthesize DNS/routing sections from forms
- only patch the selected-node outbound when the config opts into that by
  containing tag `proxy`

### What to do with unsupported nodes

If selected node conversion cannot produce a native sing-box outbound, show a
clear error and abort connect for that path. Do not silently switch to the old
hybrid generator in this V1 unless that fallback is already trivial and fully
compatible with the raw-config model.

Prefer explicit failure over hidden behavior.

## Suggested Minimal UX

- page title: `sing-box`
- main editor area
- buttons:
  - `Открыть`
  - `Сохранить`
  - `Проверить JSON`
  - `Применить`
- small hint text:
  - config is raw `sing-box.json`
  - outbound tag `proxy` will be replaced by the selected server if present

## Recommended Technical Shortcut

Do not over-model this in `AppState`.

For V1, it is enough to add a couple of fields to settings or state for:

- active sing-box config file path or name
- maybe unsaved editor text handling if you choose to persist it

Do not invent a large new profile schema.
