# Архитектура

```
Браузер ──HTTP──▶ FastAPI (app/main.py)
                    │  basic auth, security headers, статика
                    ├── /api/scan ───────▶ nmap (поиск SSH, баннер → Debian)
                    ├── /api/inventory ──▶ ansible-inventory (разбор INI/YAML)
                    ├── /api/jobs ───────▶ ansible-playbook collect.yml ──SSH──▶ хосты
                    │                         └─ collector.sh (только чтение)
                    └── /api/reports ────▶ analyze.py ◀── SQLite (vulndb.py)
                                                           ▲  Debian tracker · KEV · EPSS · NVD
```

- **Состояние.** Отчёты и базы уязвимостей — в `AMBER_DATA` (SQLite, файлы). Состояние выполняющихся заданий и passphrase ключа — в памяти процесса. Поэтому один экземпляр и стратегия `Recreate` в Kubernetes.
- **Сбор.** `collect.yml` запускает `collector.sh` модулем `script` (без Python на цели); callback-плагин `amber.py` отдаёт прогресс по хостам. Вывод разбирает `parser.py`.
- **Анализ.** `analyze.py` сопоставляет пакеты с CVE по исходному пакету и версии (`debver.py` — реализация сравнения dpkg), присваивает уровни (urgency → CVSS → без оценки; KEV и EPSS повышают), добавляет находки конфигурации (EOL, ssh, TLS, диски, reboot-required).
- **Фиды.** `vulndb.py` потоково (ijson) импортирует ~60 МБ JSON трекера в SQLite.
- **Контейнер.** UID 10001, tini как PID 1, `/tmp` и `/home/amber` — на tmpfs/emptyDir при read-only rootfs.
