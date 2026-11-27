#!/usr/bin/env python3
"""Build the pinned sing-box source with the verified full-datagram patch."""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import tempfile
import shutil

from prepare_sing_udp_patch import extract_module, prepare, sha256


PROCESS_LOOKUP_PATCH = "singbox-process-lookup-cache.patch"
# Прямые HTTPS-запросы приложения сетевым стеком Chromium (`tools browser-fetch`):
# только новые файлы, общий патч с Android (там — 0007 в series).
BROWSER_FETCH_PATCH = "browser-fetch.patch"
# «Маскировка», пакеты-обманки: движок common/kvndesync (тот же, что Android 0017) и опция
# маршрута `kvn_desync` для сокета VPN-сервера (беспорядок, разрез); обманка — штатный tls_spoof.
KVN_DESYNC_PATCH = "kvn-desync.patch"
# IPv6 к серверу первым: память семейства адресов (common/familymemory, тот же код, что
# Android 0020) для гонки sing-box и прямого outbound, сброс при смене сети.
ADDRESS_FAMILY_PATCH = "address-family-memory.patch"
# Вход через Cloudflare WARP (решение владельца 2026-11-25): endpoint `warp` получает `mtu` и закрытый файл аккаунта
# `profile.cache_path` (тот же код, что Android 0022), по умолчанию ходит на выданный аккаунту адрес.
WARP_ENTRY_PATCH = "warp-entry-profile.patch"
# Старт endpoint WARP с проверкой: если туннель не ответил (около четверти запусков аккаунта молчат, пока не сменится
# порт отправителя), endpoint пересобирается с новым сокетом и другим адресом аккаунта (тот же код, что Android 0023).
WARP_RECOVERY_PATCH = "warp-entry-recovery.patch"
# Смена сети доходит до WireGuard внутри endpoint WARP: обёртка передаёт InterfaceUpdated внутреннему endpoint (тот же код,
# что Android 0024), иначе после перехода Wi-Fi/мобильная сеть сокет туннеля остаётся на старой сети.
WARP_INTERFACE_PATCH = "warp-entry-interface-update.patch"
# Восемь кандидатов старта вместо четырёх и память об адресе, который ответил (решение владельца 2026-11-26: цензор
# блокирует адрес аккаунта, а другие адреса и порты WARP работают): после адреса аккаунта идут другие края WARP, удачный
# край хранится рядом с файлом аккаунта и пробуется первым (тот же код, что Android 0025).
WARP_CANDIDATES_PATCH = "warp-entry-candidates.patch"
# MASQUE как запасной вход (решение владельца 2026-11-26, «WARP не работает на мобильной сети»): оператор пропускает первые
# пакеты WireGuard и обрывает поток. После WireGuard endpoint пробует туннель MASQUE ядра (QUIC, затем HTTP/2 по TCP 443) и
# при тишине рабочего туннеля переходит на следующего кандидата (тот же код, что Android 0026).
WARP_MASQUE_PATCH = "warp-entry-masque.patch"
# Поле 2026-11-26 (диагностика Android 0.6.62): замена умершего WireGuard-туннеля ждала 30 с, потому что проверка старта
# считалась «недавним успехом», а аккаунт MASQUE ядро регистрировало само, и запрос обрывался на 7 с. Теперь тихого окна нет
# до первого настоящего соединения, а аккаунт без файла получает 20 с (тот же код, что Android 0027).
WARP_MASQUE_TIMING_PATCH = "warp-entry-masque-timing.patch"
# Поле 2026-11-26 (диагностика Android 0.6.63): оператор не пускает api.cloudflareclient.com по имени в TLS. Туннель MASQUE
# берёт имя сервера любым (проверено на настоящем Cloudflare: www.cloudflare.com, yandex.ru, example.com, QUIC и HTTP/2), поэтому
# кандидаты идут сначала с подставным именем, HTTP/2 раньше QUIC (тот же код, что Android 0028).
WARP_MASQUE_SNI_PATCH = "warp-entry-masque-sni.patch"
# Поле 2026-11-27 (диагностика Android 0.6.65, мобильная сеть): туннель WARP не пропускал трафик ни по WireGuard, ни по MASQUE на
# адресах 162.159.192.x и 162.159.198.2. Владелец: «попробовать больше диапазонов адресов и портов». Больше кандидатов: другие
# адреса блока MASQUE (HTTP/2 отвечает на 162.159.198.2-50, проверено на настоящем Cloudflare), IPv6, третий блок WireGuard
# 162.159.195.x и другие порты; после отказа WireGuard пробуется другой блок адресов, а не тот же (тот же код, что Android 0030).
WARP_MASQUE_EDGES_PATCH = "warp-entry-masque-edges.patch"
# Владелец 2026-11-27: «WARP должен пробиваться отовсюду». Другие края Cloudflare, которые сервис присылает заголовком подписки
# `zapret-warp-edges` (network/warp_edges.py), ядро получает опцией `extra_edges` endpoint-а и пробует сразу после двух первых
# адресов аккаунта: новые адреса и порты находятся без выпуска приложения (тот же код, что Android 0031).
WARP_EXTRA_EDGES_PATCH = "warp-entry-extra-edges.patch"
# Signs that upstream already stopped scanning the whole connection table per
# lookup (sing dev 4ca3bebe: keyed TCP owner lookup; any table cache/single-flight).
UPSTREAM_OWNER_LOOKUP_MARKERS = ("FindSocketOwner", "nsiGetTCPConnection", "singleflight")
_OWN_FILE_PREFIX = "zapret_"


class StaleProcessLookupPatch(RuntimeError):
    """The Windows process-lookup patch no longer matches the pinned upstream."""


def _git_blob_id(path: Path) -> str:
    data = path.read_bytes()
    return hashlib.sha1(b"blob %d\0" % len(data) + data).hexdigest()


def apply_process_lookup_patch(source: Path, patch: Path) -> None:
    """Apply the patch only to the exact upstream files it was written for."""
    apply_exact_patch(source, patch, what="поиск процесса", port_hint=(
        f"перенесите патч {patch.name} на новую версию или удалите его, "
        "если upstream исправил поиск сам"))


def apply_exact_patch(source: Path, patch: Path, *, what: str, port_hint: str) -> None:
    """`git apply` only onto the exact upstream blobs named in the patch's full index lines."""
    text = patch.read_text(encoding="utf-8")
    bases = re.findall(r"^diff --git a/(\S+) b/\S+\n(?:(?:new|deleted) file mode \d+\n)?index ([0-9a-f]{40})\.\.",
                       text, re.MULTILINE)
    if not bases:
        raise StaleProcessLookupPatch(f"{patch.name}: нет полных index-строк (git diff --full-index)")
    for name, blob in bases:
        target = source / name
        if blob == "0" * 40:
            if target.exists():
                raise StaleProcessLookupPatch(f"upstream изменил {what}: {name} уже существует — {port_hint}")
            continue
        actual = _git_blob_id(target) if target.is_file() else "нет файла"
        if actual != blob:
            raise StaleProcessLookupPatch(
                f"upstream изменил {what}: {name} (blob {actual}, патч написан для {blob}) — {port_hint}")
    check = subprocess.run(["git", "apply", "--check", str(patch)], cwd=source, capture_output=True, text=True)
    if check.returncode != 0:
        raise StaleProcessLookupPatch(
            f"upstream изменил {what}: git apply --check не прошёл ({check.stderr.strip()}) — {port_hint}")
    subprocess.run(["git", "apply", str(patch)], cwd=source, check=True)


def assert_process_lookup_patch_needed(*roots: Path) -> None:
    """Stop when the sources already carry an upstream owner-lookup fix."""
    for root in roots:
        for directory in (root / "common/process", root / "common/winiphlpapi"):
            if not directory.is_dir():
                continue
            for path in sorted(directory.glob("*.go")):
                if path.name.startswith(_OWN_FILE_PREFIX):
                    continue
                content = path.read_text(encoding="utf-8", errors="replace")
                for marker in UPSTREAM_OWNER_LOOKUP_MARKERS:
                    if marker in content:
                        raise StaleProcessLookupPatch(
                            f"патч {PROCESS_LOOKUP_PATCH}, вероятно, устарел: в {path.relative_to(root).as_posix()} "
                            f"есть upstream-признак «{marker}» — проверьте upstream-исправление и удалите или перенесите патч")


def assert_no_build_paths(binary: Path, *paths: Path) -> None:
    """Stop when the binary embeds a temporary build directory.

    Such a path differs per build, so the core would change in every release
    even when no source changed, and delta updates could not skip it.
    """
    data = binary.read_bytes()
    for path in paths:
        text = str(path.resolve())
        for needle in {text, text.replace("\\", "/")}:
            if needle.encode() in data or needle.encode("utf-16-le") in data:
                raise ValueError(f"{binary.name} embeds the build directory {needle}: build is not reproducible")


def build(lock_path: Path, output: Path, work: Path, go: str) -> dict:
    lock = json.loads(lock_path.read_text(encoding="utf-8"))
    pin = lock["singbox_build"]
    upstream = next(s for s in lock["sources"] if s["id"] == "sing-box-extended")
    if upstream["version"] != pin["version"]:
        raise ValueError("sing-box archive and source revision differ")
    manifest = Path(__file__).resolve().parents[1] / "core-patches/sing-udp.json"
    if sha256(manifest) != pin["udp_manifest_sha256"]:
        raise ValueError("sing-box UDP manifest differs from release lock")
    module = json.loads(subprocess.check_output(
        [go, "mod", "download", "-json", f'{pin["module"]}@{pin["version"]}'], text=True))
    if (module["Sum"] != pin["module_sum"] or module["GoModSum"] != pin["module_go_mod_sum"]
            or module["Origin"]["Hash"] != pin["commit"]
            or sha256(Path(module["Zip"])) != pin["zip_sha256"]):
        raise ValueError("sing-box source provenance mismatch")
    work.mkdir(parents=True, exist_ok=True)
    stage = Path(tempfile.mkdtemp(prefix="singbox-build-", dir=work))
    source = stage / "source"
    extract_module(module, source)
    dns_patch = manifest.parent / 'singbox-dns-fallback-warning.patch'
    subprocess.run(['git', 'apply', '--check', str(dns_patch)], cwd=source, check=True)
    subprocess.run(['git', 'apply', str(dns_patch)], cwd=source, check=True)
    shutil.copyfile(manifest.parent / 'singbox_dns_fallback_test.go', source / 'dns/transport/fallback/zapret_fallback_test.go')
    # Windows connection-owner lookup: cached raw table + shared refresh.
    process_patch = manifest.parent / PROCESS_LOOKUP_PATCH
    apply_process_lookup_patch(source, process_patch)
    shutil.copyfile(manifest.parent / 'singbox_process_lookup_test.go', source / 'common/process/zapret_pid_table_cache_test.go')
    browser_patch = manifest.parent / BROWSER_FETCH_PATCH
    subprocess.run(['git', 'apply', '--check', str(browser_patch)], cwd=source, check=True)
    subprocess.run(['git', 'apply', str(browser_patch)], cwd=source, check=True)
    desync_patch = manifest.parent / KVN_DESYNC_PATCH
    apply_exact_patch(source, desync_patch, what="маршрутные опции", port_hint=(
        f"перенесите патч {desync_patch.name} на новую версию sing-box"))
    family_patch = manifest.parent / ADDRESS_FAMILY_PATCH
    apply_exact_patch(source, family_patch, what="набор адресов сервера", port_hint=(
        f"перенесите патч {family_patch.name} на новую версию sing-box"))
    warp_patch = manifest.parent / WARP_ENTRY_PATCH
    apply_exact_patch(source, warp_patch, what="endpoint WARP", port_hint=(
        f"перенесите патч {warp_patch.name} на новую версию sing-box"))
    recovery_patch = manifest.parent / WARP_RECOVERY_PATCH
    apply_exact_patch(source, recovery_patch, what="старт endpoint WARP", port_hint=(
        f"перенесите патч {recovery_patch.name} на новую версию sing-box"))
    interface_patch = manifest.parent / WARP_INTERFACE_PATCH
    apply_exact_patch(source, interface_patch, what="уведомление endpoint WARP о смене сети", port_hint=(
        f"перенесите патч {interface_patch.name} на новую версию sing-box"))
    candidates_patch = manifest.parent / WARP_CANDIDATES_PATCH
    apply_exact_patch(source, candidates_patch, what="кандидаты старта endpoint WARP", port_hint=(
        f"перенесите патч {candidates_patch.name} на новую версию sing-box"))
    masque_patch = manifest.parent / WARP_MASQUE_PATCH
    apply_exact_patch(source, masque_patch, what="запасной вход MASQUE endpoint WARP", port_hint=(
        f"перенесите патч {masque_patch.name} на новую версию sing-box"))
    masque_timing_patch = manifest.parent / WARP_MASQUE_TIMING_PATCH
    apply_exact_patch(source, masque_timing_patch, what="время замены туннеля MASQUE", port_hint=(
        f"перенесите патч {masque_timing_patch.name} на новую версию sing-box"))
    masque_sni_patch = manifest.parent / WARP_MASQUE_SNI_PATCH
    apply_exact_patch(source, masque_sni_patch, what="имя сервера в TLS туннеля MASQUE", port_hint=(
        f"перенесите патч {masque_sni_patch.name} на новую версию sing-box"))
    masque_edges_patch = manifest.parent / WARP_MASQUE_EDGES_PATCH
    apply_exact_patch(source, masque_edges_patch, what="другие адреса и порты входа WARP", port_hint=(
        f"перенесите патч {masque_edges_patch.name} на новую версию sing-box"))
    extra_edges_patch = manifest.parent / WARP_EXTRA_EDGES_PATCH
    apply_exact_patch(source, extra_edges_patch, what="другие края WARP от сервиса", port_hint=(
        f"перенесите патч {extra_edges_patch.name} на новую версию sing-box"))
    dependency = prepare(source, stage / "dependency", manifest, go)
    assert_process_lookup_patch_needed(source, dependency)
    # Go записывает путь замены модуля в сам exe (go version -m). Абсолютный путь
    # временной папки делал каждую сборку sing-box.exe уникальной (~33 МБ в каждом
    # обновлении); относительный от source одинаков при любой временной папке.
    replacement = os.path.relpath(dependency, source).replace(os.sep, "/")
    if not replacement.startswith("../"):
        raise ValueError(f"patched dependency must sit next to the source tree, got {replacement}")
    subprocess.run([go, "mod", "edit", f"-replace=github.com/sagernet/sing={replacement}"], cwd=source, check=True)
    subprocess.run([go, 'test', '-mod=readonly', './dns/transport/fallback', '-run', '^TestZapret', '-count=1'], cwd=source, check=True)
    subprocess.run([go, 'test', '-mod=readonly', './common/process', '-run', '^TestZapret', '-count=1'], cwd=source, check=True)
    tags = (source / "release/DEFAULT_BUILD_TAGS").read_text().strip() + ",with_purego"
    # Без libcronet рядом тест ClientHello пропускается, остальные идут всегда.
    subprocess.run([go, 'test', '-mod=readonly', '-tags', tags, './common/browserfetch', '-run', '^TestZapret', '-count=1'],
                   cwd=source, check=True, env={**os.environ, "CGO_ENABLED": "0"})
    # route/rule links tfo-go, whose linkname needs the release's -checklinkname=0 (release/LDFLAGS).
    subprocess.run([go, 'test', '-mod=readonly', '-tags', tags, '-ldflags=-checklinkname=0',
                    './common/kvndesync', './route/rule', '-count=1'],
                   cwd=source, check=True, env={**os.environ, "CGO_ENABLED": "0"})
    subprocess.run([go, 'test', '-mod=readonly', './common/familymemory', './common/dialer', '-count=1'],
                   cwd=source, check=True)
    # protocol/warp links tfo-go on Windows, whose linkname needs the release's -checklinkname=0 (release/LDFLAGS).
    subprocess.run([go, 'test', '-mod=readonly', '-tags', tags, '-ldflags=-checklinkname=0', './protocol/warp', '-count=1'],
                   cwd=source, check=True, env={**os.environ, "CGO_ENABLED": "0"})
    for tags_variant in ("", "with_low_memory"):
        subprocess.run([go, "test", "-mod=readonly", "-tags", tags_variant,
                        "github.com/sagernet/sing/common/network", "-run", "^TestZapret", "-count=1"],
                       cwd=source, check=True)
    flags = (source / "release/LDFLAGS").read_text().strip()
    flags += f' -X github.com/sagernet/sing-box/constant.Version={pin["version"].removeprefix("v")} -s -w -buildid='
    # Воспроизводимая сборка: без путей, без VCS-меток, без build ID, без cgo.
    reproducible_env = {**os.environ, "CGO_ENABLED": "0", "GOFLAGS": "", "GOTOOLCHAIN": "local"}
    subprocess.run([go, "build", "-mod=readonly", "-trimpath", "-buildvcs=false", "-tags", tags,
                    "-ldflags", flags, "-o", str(output.resolve()), "./cmd/sing-box"],
                   cwd=source, check=True, env=reproducible_env)
    assert_no_build_paths(output, stage, work)
    assert_browser_fetch_command(output)
    provenance = {**pin, "go": subprocess.check_output([go, "env", "GOVERSION"], text=True).strip(),
                  "goos": os.environ.get("GOOS", ""), "goarch": os.environ.get("GOARCH", ""),
                  "build_tags": tags, "binary_sha256": sha256(output),
                  "udp_patch": json.loads((dependency.parent / "provenance.json").read_text()),
                  "dns_warning_patch_sha256": sha256(dns_patch),
                  "process_lookup_patch_sha256": sha256(process_patch),
                  "browser_fetch_patch_sha256": sha256(browser_patch),
                  "kvn_desync_patch_sha256": sha256(desync_patch),
                  "address_family_patch_sha256": sha256(family_patch),
                  "warp_entry_patch_sha256": sha256(warp_patch),
                  "warp_recovery_patch_sha256": sha256(recovery_patch),
                  "warp_interface_patch_sha256": sha256(interface_patch),
                  "warp_candidates_patch_sha256": sha256(candidates_patch),
                  "warp_masque_patch_sha256": sha256(masque_patch),
                  "warp_masque_timing_patch_sha256": sha256(masque_timing_patch),
                  "warp_masque_sni_patch_sha256": sha256(masque_sni_patch),
                  "warp_masque_edges_patch_sha256": sha256(masque_edges_patch),
                  "warp_extra_edges_patch_sha256": sha256(extra_edges_patch)}
    output.with_suffix(".build.json").write_text(json.dumps(provenance, indent=2) + "\n", encoding="utf-8")
    return provenance


def assert_browser_fetch_command(binary: Path) -> None:
    """В собранном ядре есть `tools browser-fetch` (проверка без сети и без libcronet)."""
    if os.name != "nt":
        return  # сборка релиза идёт на win10; чужой exe здесь не запустить
    reply = subprocess.run([str(binary), "tools", "browser-fetch"], input='{"url":"http://example.com/"}',
                           capture_output=True, text=True, timeout=60)
    if "only https" not in reply.stdout:
        raise RuntimeError(f"sing-box без browser-fetch: {reply.stdout.strip()[:200]} {reply.stderr.strip()[:200]}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--lock", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--work", type=Path, required=True)
    parser.add_argument("--go", default="go")
    args = parser.parse_args()
    build(args.lock.resolve(), args.output.resolve(), args.work.resolve(), args.go)
