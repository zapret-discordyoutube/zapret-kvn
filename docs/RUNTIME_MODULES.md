# Protocol runtimes and original errors

The source layout on both platforms is documented in
[SOURCE_LAYOUT.md](SOURCE_LAYOUT.md). The folder migration is complete;
WG/AWG transport validation and the combined stable release are separate gates.

The transport owner is fixed on both platforms: VLESS → official Xray core,
Hysteria2 → official Hysteria core, WG/AWG → official Amnezia device/netstack,
remaining protocols → sing-box. Plain WG uses Amnezia with AWG extensions absent.
The only routing, DNS and TUN owner on both platforms is sing-box. Its active native JSON
owns domain rules and geosite-derived native `.srs` rule sets in both proxy and
TUN modes. Xray and Hysteria implement only the selected proxy transport, never
a second routing policy. Core selection is not a
capability probe or an automatic fallback between protocol implementations.

Protocol adapters retain the original imported URI. Xray needs native JSON,
so its adapter translates the URI at that boundary; it must not translate it
through sing-box first. On Android the cores are embedded libraries behind
the same outbound interface; sing-box owns the only TUN and protected sockets.

Legacy Windows Xray-front and tun2socks selections migrate to sing-box. Existing
raw Xray configuration files are retained, not translated or overwritten. Auto
connect is disabled during that migration: users must review their sing-box
rules before explicitly reconnecting. Existing sing-box users keep auto connect.

## Errors

`xray_fluent/diagnostics/runtime-errors.json` and Android's
`app/src/main/resources/runtime-errors.json` are the same catalog. An error is
evidence first: component, operation stage, original message, session generation
and a target identity only when the producer can prove it. The catalog supplies
classification, never replacement prose. Unknown messages remain visible.

The error journal is separate from bounded traffic/debug logs. It retains each
distinct error during the application process lifetime and counts repeats.
The UI and diagnostic export use this journal without the traffic-log limit.
Passwords, private keys, tokens and credential-bearing URIs are redacted.
Release verification must exercise real producer → observer → journal → UI/
export boundaries; direct reducer tests alone do not verify this contract.

Loopback TCP resets/EOF are retained as `LOCAL_CLIENT_CONNECTION_CLOSED` with
`record_only` policy. They cannot consume Hysteria recovery or turn successful
HTTPS readiness into a server failure. A real process exit remains terminal;
TLS/auth/pin failures retain their higher-priority security classification.

## Source-built sing-box UDP fix

`core-patches/sing-udp.json` pins upstream sing module versions, zip/patch hashes
and the packet regression test shared with Android. The private patched module
receives complete UDP datagrams in both normal and low-memory builds, reserves
transport header space in addition to payload, and uses packet-size buffers for
connected UDP read waiters. TCP buffers are unchanged. UDP buffers grow to
64 KiB (plus required header space), so in-flight UDP memory use increases.

The Go cache is never patched in place. An unknown dependency version or changed
cached source fails the build. Windows bundle cache keys include adapter source,
patches, tests and build tools, not only upstream versions. Android AAR freshness
includes `CORE_UDP_PATCH_SHA256`. Remove the patch only after the same full-chain
packet tests pass against an upstream fix.

## Coordinated stable preparation

Before validation and the final source commits, run from the Windows checkout:

```bash
python3 scripts/prepare_core_release.py --windows-version 0.5.8 --android-tag v0.3.27
```

Use the next actual unpublished versions. Each new pair checks official upstream
tags (Amnezia prereleases allowed), updates the two pins and writes the identical
`core-release-freeze.json` to both repositories. Repeating that pair validates
the receipt offline, without selecting a newer tag. API/dependency incompatibility
must be repaired and tested before committing or publishing; no old-core fallback.

Then run all platform gates, commit/push all ready source and use the existing
Windows runner and Android stable publisher. The Windows runner reuses a matching
freeze; the Android publisher requires its tagged source to match the freeze.
Installed apps receive these built cores with the app update only.

## Android audit observations

The existing Hysteria adapter emits `server certificate SHA-256 mismatch` but
the old Android classifier required the substring `pin`. It therefore lost
the security classification and could show the subsequent generic HTTPS failure
as VPN-200. The shared catalog covers the adapter and official executable texts.

The protected domain UDP dialer returns a NAT wrapper that loses the numeric
sender address (`127.0.0.1:port` becomes `:port`). A loopback boundary test
reproduces this. A local official Hysteria plain handshake and TCP echo still
pass through that wrapper, so this is not proof of the reported device failure.
Android ADB is currently unavailable; no device reproduction has been claimed.
