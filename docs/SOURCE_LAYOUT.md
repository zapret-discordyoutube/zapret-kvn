# Карта исходников

Раскладка Windows и Android выполнена 2026-09-05. Это структурный перенос:
он не меняет маршрутизацию, формат данных или статус готовности нового WG/AWG
runtime. Старых модулей-переадресаций в корне нет.

## Windows

```text
xray_fluent/
├── __init__.py, constants.py   общая идентичность и константы
├── application/               контроллер, сессии, переключения, сценарии
├── client_reports/            отчёты о подключениях для status.zapret.moe (docs/CLIENT_REPORTS.md)
├── engines/
│   ├── singbox/               routing/DNS/TUN и native-протоколы
│   ├── xray/                  VLESS transport
│   ├── hysteria/              Hysteria transport и runtime contract
│   ├── amnezia/               WG/AWG sidecar lifecycle
│   └── zapret/                запуск и параметры Zapret
├── profiles/                  модели, хранение, пути, метаданные/пресеты
├── importer/                  ключи, подписки, QR и адаптеры форматов
├── diagnostics/               исходные ошибки, журнал, экспорт, метрики
├── network/                   HTTP, readiness, ping, speed и network workers
├── platform/windows/          системный прокси, процессы, адаптеры, автозапуск
├── updates/                   проверка и установка обновлений
└── ui/                        окна, страницы и виджеты
runtime/amnezia/               отдельный Go-модуль официального WG/AWG реле
```

Точка координации — `application/controller.py`. Исходные ошибки и их каталог —
`diagnostics/runtime_errors.py` и `diagnostics/runtime-errors.json`.
Они упаковываются вместе; экспорт не зависит от прежнего расположения файлов.
Разрешение ресурсов разработки и путь автозапуска остаются от корня проекта.

## Android

Внутри `app/src/main/java/io/github/zapretkvn/android`:

- `vpn/`: VPN service/controller/state/recovery и системная Quick Settings service.
- `engines/singbox/`, `engines/hysteria/`: Kotlin-интеграция и контракты ядер.
- `network/`, `network/probes/`: underlying network, DNS, health, latency.
- `platform/`: Android TUN/socket adapter и системная VPN policy.
- `apps/`: обнаружение, выбор приложений и per-app scope.
- `diagnostics/`: журнал исходных ошибок, метрики и безопасный экспорт.
- `profiles/`, `importer/`, `config/`, `routing/`, `updates/`, `ui/`:
  существующие функциональные пакеты сохранены.

Встроенные Go-адаптеры Android Xray/Amnezia находятся в воспроизводимых
`core-patches`, а не в пустых Kotlin-пакетах. Чистые модули решений: `runtime-log`
(журнал) и `client-reports` (отчёты о подключениях, `docs/CLIENT_REPORTS.md` Android).
Имена Android VPN-сервиса/плитки, applicationId и пути данных не изменены.

## Проверка структуры

Windows: `python3 -m unittest discover -s tests`.
Android: `scripts/verify-project.sh`, `:app:testDebugUnitTest`,
`:app:assembleDebugAndroidTest`. Сборка instrumentation APK не означает,
что тесты были выполнены на устройстве. Выпуск приложений — отдельная операция.

## Site names of the updater (owner 2026-11-19)

`updates/` reaches Forgejo only through the shared update core `zapret_update/mirrors.py`, a byte-for-byte copy of
Zapret 2 GUI's `public_zapretgui/src/zapret_update` (sync with `scripts/sync_update_core.py`, never edit the copy).
Russia cuts the whole zone `zapret.moe` by name (SNI), so the core accepts one label under any domain of the
zapret-links pool: its seed starts with names on `fuckingspeedtest.com`, and further domains come from `domains`
of a trusted list (`/_sites/mirrors.json`, the entry pages). Release files are trusted only on such learnt or seed
names (`app_updater._is_trusted_release_url`); `tests/test_update_pool_mirrors.py` shows an update found and
trusted when only pool names answer.
