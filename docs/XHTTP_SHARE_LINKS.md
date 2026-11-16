# VLESS XHTTP share links

Owner of the protocol: the native Xray core. The importer (`xray_fluent/importer/link_parser.py`,
`_build_xhttp_settings`) only writes Xray's own `xhttpSettings` object; it does not interpret it.

| Link parameter | Written to | Notes |
| --- | --- | --- |
| `type=xhttp` (or the old `splithttp`) | `streamSettings.network = "xhttp"` | `splithttp` is renamed so the rest of the app compares one name. |
| `path` | `xhttpSettings.path` | |
| `host` | `xhttpSettings.host` | |
| `mode` | `xhttpSettings.mode` | Lower-cased; only `auto`, `packet-up`, `stream-up`, `stream-one`, anything else is a Russian import error (Xray would refuse to start). Absent means Xray's default (`auto`). |
| `extra` | `xhttpSettings.extra` | XTLS share-link standard: `encodeURIComponent(JSON object)`. Kept verbatim, field names are not touched (`xPaddingObfsMode`, `uplinkHTTPMethod`, `xmux`, `downloadSettings`…). `extra=null`, empty or `{}` mean unset; invalid JSON or a non-object is an import error. |

How Xray reads it (`infra/conf/transport_method.go`, `SplitHTTPConfig.Build`): when `extra` is present it
replaces the whole XHTTP config, then `host`, `path` and `mode` from the outer object are put back on top.
So a field must live either in `extra` or beside `path`, never both with different meaning.

Masking (`docs/MASKING.md`) writes `xmux` into `xhttpSettings.extra` when `extra` exists, otherwise into
`xhttpSettings`; both shapes come out of this importer.

Stored nodes: before this change the importer dropped path, host, mode and extra, so nodes saved by 0.8.80
and older carry an `xhttpSettings`-less outbound. `prepare_node_for_runtime` re-parses every node's link
before it starts (`repair_node_outbound_from_link`), so such nodes are repaired on the next connect and
saved; no re-import is needed. Nodes without a link (pasted JSON) already hold native settings.

Not covered: VMess/Trojan over XHTTP (sing-box has no XHTTP transport in the Windows build, the node is
marked unsupported), and the `fm` share-link parameter (Xray finalmask JSON), which neither platform imports.
