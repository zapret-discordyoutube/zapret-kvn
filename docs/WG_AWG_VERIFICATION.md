# WG/AWG transport verification — 2026-09-06

Release pair: Windows 0.5.8 / Android 0.3.27. Version selection is recorded in
`core-release-freeze.json`; this is a source pin, not a device-test attestation.

## Verified before source commit

- Official Amnezia `v3.1.20260828`, commit
  `b5928efb6ca19f0153958460c3d141f04abc5c2e`, on both platforms.
- Windows portable host suite: 814 tests, 5 platform-dependent skips, no failures.
- Android host suites: app 336, wireguard-import 8, network-bootstrap 3,
  app-updater 15 tests; no failures. Instrumentation APK assembled.
- Android core built for arm64-v8a, armeabi-v7a and x86_64; native arm64 symbols
  checked against the production AAR; core provenance/cache verification passed.
- Actual Windows x64 Go tests exercised official WG, AWG2 and AWG3.1 encrypted
  TCP/UDP, authenticated relay association ownership and three child-process
  start/parent-pipe-close cycles with port reuse.
- The real sing-box -> relay -> official AWG chain passed controlled HTTPS with
  certificate validation, delegated DNS, direct/proxy/block route assertions and
  UDP payloads of 1200, 8193, 16385, 20000 and 65497 bytes. Equivalent host builds
  of both pinned sing-box versions passed. Linux Go race tests also passed.
- The Windows core-bundle builder ran on Windows and produced a verified archive;
  the production release runner performs its own exact-source dev/stable gates.
- Shared WG/AWG import/native JSON/UAPI golden fixtures and UDP patches match
  between repositories. Normal and low-memory UDP regression tests passed.
- New log regression: a loopback TCP reset remains in the raw error journal but
  is not a remote Hysteria failure. Windows tests traverse manager log ingestion;
  Android tests cover the shared classifier and startup-cause selection. Remote
  failures, process exits and TLS/pin failures retain their failure behavior.

## Limitations

host-verified; Android ADB device tests not verified.

No physical-device Wi-Fi/mobile transition or Android system-TUN verification
was performed. Controlled loopback transport tests do not establish reachability
of the user's servers, fix server certificates/pins, or prove that previously
reported network timeouts have disappeared. No TLS validation was disabled.
Production artifact signatures, immutable uploads and channel delivery are
verified by the respective release publishers after the ready source commit.
