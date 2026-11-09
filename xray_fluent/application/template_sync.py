from __future__ import annotations

from dataclasses import dataclass
import json
from pathlib import Path
from uuid import uuid4

from ..constants import CONFIGS_DIR, TEMPLATE_UPDATE_BUNDLE_DIR, TEMPLATES_DIR


SUPPORTED_ENGINES = ("sing-box", "xray")


@dataclass(frozen=True)
class TemplateSyncResult:
    templates_updated: tuple[str, ...] = ()
    configs_updated: tuple[str, ...] = ()
    configs_preserved: tuple[str, ...] = ()
    # Конфиги, у которых правила DNS ссылались на не объявленные в route наборы
    # правил: такие правила убраны, иначе ядро отказывается стартовать.
    configs_repaired: tuple[str, ...] = ()
    # Разделы, которые шаблон обновил, а пользователь правил вручную: новая
    # версия раздела к его конфигу не применена. ((ключ конфига, (разделы…)), …)
    stale_sections: tuple[tuple[str, tuple[str, ...]], ...] = ()

    @property
    def changed(self) -> bool:
        return bool(self.templates_updated or self.configs_updated or self.configs_repaired)


def _same_json_document(left: Path, right: Path) -> bool:
    try:
        left_payload = json.loads(left.read_text(encoding="utf-8-sig"))
        right_payload = json.loads(right.read_text(encoding="utf-8-sig"))
    except (OSError, UnicodeError, json.JSONDecodeError):
        try:
            return left.read_bytes() == right.read_bytes()
        except OSError:
            return False
    return left_payload == right_payload


def _same_bytes(left: Path, right: Path) -> bool:
    try:
        return left.read_bytes() == right.read_bytes()
    except OSError:
        return False


def _atomic_copy(source: Path, target: Path) -> bool:
    payload = source.read_bytes()
    return _atomic_write(payload, target)


def _atomic_write(payload: bytes, target: Path) -> bool:
    if target.is_file() and target.read_bytes() == payload:
        return False

    target.parent.mkdir(parents=True, exist_ok=True)
    temporary = target.with_name(f".{target.name}.{uuid4().hex}.tmp")
    try:
        temporary.write_bytes(payload)
        temporary.replace(target)
    finally:
        temporary.unlink(missing_ok=True)
    return True


def _load_json_object(path: Path) -> dict | None:
    try:
        payload = json.loads(path.read_text(encoding="utf-8-sig"))
    except (OSError, UnicodeError, json.JSONDecodeError):
        return None
    return payload if isinstance(payload, dict) else None


_MISSING = object()


def merge_stock_sections(active: dict, previous: dict, current: dict) -> dict:
    """Three-way merge of top-level native sections.

    A section the user left equal to the previously shipped template follows the
    new template (added, replaced or removed with it). A section the user edited
    is kept verbatim. Keys only the user added are kept. Order follows the
    active document, new stock sections are appended in template order.
    """

    merged: dict = {}
    for key, value in active.items():
        if key in current or key in previous:
            if value == previous.get(key, _MISSING):
                if key in current:
                    merged[key] = current[key]
                continue
        merged[key] = value
    for key, value in current.items():
        if key not in merged and key not in active and key not in previous:
            merged[key] = value
    # Sections are coupled: DNS rules point at rule sets declared in ``route``.
    # If the new stock DNS would name a rule set the user's route does not have
    # (the user edited route, so it did not follow the stock), the core would
    # refuse to start. Keep the user's previous DNS section instead.
    if "dns" in merged and merged["dns"] != active.get("dns", _MISSING) and has_dangling_dns_rule_sets(merged):
        if "dns" in active:
            merged["dns"] = active["dns"]
        else:
            del merged["dns"]
    return merged


def _rule_set_refs(rule: object) -> set[str]:
    """Rule-set tags a DNS/route rule refers to, including nested logical rules."""

    refs: set[str] = set()
    if not isinstance(rule, dict):
        return refs
    names = rule.get("rule_set")
    if isinstance(names, str):
        refs.add(names)
    elif isinstance(names, list):
        refs.update(name for name in names if isinstance(name, str))
    nested = rule.get("rules")
    if isinstance(nested, list):
        for child in nested:
            refs |= _rule_set_refs(child)
    return refs


def _declared_rule_sets(document: dict) -> set[str]:
    route = document.get("route")
    declared = route.get("rule_set") if isinstance(route, dict) else None
    if not isinstance(declared, list):
        return set()
    return {item["tag"] for item in declared if isinstance(item, dict) and isinstance(item.get("tag"), str)}


def _dns_rules(document: dict) -> list:
    dns = document.get("dns")
    rules = dns.get("rules") if isinstance(dns, dict) else None
    return rules if isinstance(rules, list) else []


def has_dangling_dns_rule_sets(document: dict) -> bool:
    """True when a DNS rule names a rule set that ``route.rule_set`` does not declare.

    sing-box refuses such a config at start ("dns rule[N]: rule-set not found").
    """

    declared = _declared_rule_sets(document)
    return any(_rule_set_refs(rule) - declared for rule in _dns_rules(document))


def drop_dangling_dns_rules(document: dict) -> dict:
    """Copy of ``document`` without the DNS rules that name undeclared rule sets.

    The remaining rules and ``dns.final`` keep working, so a name that lost its
    dedicated rule is resolved by the final server, as before the rules existed.
    """

    declared = _declared_rule_sets(document)
    kept = [rule for rule in _dns_rules(document) if not (_rule_set_refs(rule) - declared)]
    return {**document, "dns": {**document["dns"], "rules": kept}}


def _dump_json(payload: dict) -> bytes:
    return (json.dumps(payload, ensure_ascii=False, indent=2) + "\n").encode("utf-8")


def _repair_dangling_dns_rules(active_config: Path, bundled_path: Path) -> bool:
    """Undo the damage of an older merge that left stock DNS rules without their rule sets.

    Version 0.8.67 added ``dns.rules`` that name rule sets from ``route``. A user
    who had edited ``route`` kept it verbatim, took the new DNS and got
    "rule-set not found" at start. Only a DNS section equal to the shipped one
    is touched (it is ours); a DNS the user wrote is never rewritten.
    """

    if not active_config.is_file():
        return False
    active = _load_json_object(active_config)
    current = _load_json_object(bundled_path)
    if active is None or current is None or "dns" not in active:
        return False
    if active["dns"] != current.get("dns") or not has_dangling_dns_rule_sets(active):
        return False
    return _atomic_write(_dump_json(drop_dangling_dns_rules(active)), active_config)


def sync_packaged_templates(
    *,
    bundle_dir: Path = TEMPLATE_UPDATE_BUNDLE_DIR,
    templates_dir: Path = TEMPLATES_DIR,
    configs_dir: Path = CONFIGS_DIR,
) -> TemplateSyncResult:
    """Install native templates and let untouched sections follow them.

    The self-updater deliberately preserves ``data/``. Release builds therefore
    carry the current native JSON templates under ``assets/template-update``.
    Before replacing a built-in template, compare its previous installed text
    with the same-path active config. An equivalent active copy is still stock
    and follows the new template byte for byte. Otherwise each top-level section
    (``dns``, ``route``, ``outbounds``…) that still equals the previous template
    follows the new one, and every section the user edited is preserved.
    """

    templates_updated: list[str] = []
    configs_updated: list[str] = []
    configs_preserved: list[str] = []
    configs_repaired: list[str] = []
    stale_sections: list[tuple[str, tuple[str, ...]]] = []

    for engine in SUPPORTED_ENGINES:
        bundled_root = bundle_dir / engine
        if not bundled_root.is_dir():
            continue

        for bundled_path in sorted(bundled_root.rglob("*.json")):
            if not bundled_path.is_file():
                continue

            relative = bundled_path.relative_to(bundled_root)
            key = f"{engine}/{relative.as_posix()}"
            installed_template = templates_dir / engine / relative
            active_config = configs_dir / engine / relative
            template_will_change = not _same_bytes(installed_template, bundled_path)

            # Refresh the active copy first. If startup is interrupted between
            # the two atomic writes, the active config is already on the safe
            # new version and the template write is retried next launch.
            if template_will_change and installed_template.is_file() and active_config.is_file():
                if _same_json_document(installed_template, active_config):
                    if _atomic_copy(bundled_path, active_config):
                        configs_updated.append(key)
                else:
                    active = _load_json_object(active_config)
                    previous = _load_json_object(installed_template)
                    current = _load_json_object(bundled_path)
                    if active is not None and previous is not None and current is not None:
                        merged = merge_stock_sections(active, previous, current)
                        if merged != active and _atomic_write(_dump_json(merged), active_config):
                            configs_updated.append(key)
                        if merged != current:
                            configs_preserved.append(key)
                        stale = tuple(
                            section for section in current
                            if previous.get(section, _MISSING) != current[section]
                            and merged.get(section, _MISSING) != current[section]
                        )
                        if stale:
                            stale_sections.append((key, stale))
                    elif not _same_json_document(active_config, bundled_path):
                        configs_preserved.append(key)

            if _repair_dangling_dns_rules(active_config, bundled_path):
                configs_repaired.append(key)

            if _atomic_copy(bundled_path, installed_template):
                templates_updated.append(key)

    return TemplateSyncResult(
        templates_updated=tuple(templates_updated),
        configs_updated=tuple(configs_updated),
        configs_preserved=tuple(configs_preserved),
        configs_repaired=tuple(configs_repaired),
        stale_sections=tuple(stale_sections),
    )
