# Архитектура

## Компоненты и поток данных

```
Браузер ──HTTPS──▶ reverse proxy / Ingress ──HTTP──▶ FastAPI (app/main.py)
                                                       │  basic auth, заголовки безопасности, статика
                                                       ├── /api/scan ──────▶ nmap: поиск SSH, баннер → релиз Debian
                                                       ├── /api/inventory ─▶ ansible-inventory: разбор INI/YAML
                                                       ├── /api/jobs ──────▶ ansible-playbook collect.yml ──SSH──▶ хосты
                                                       │                        └─ collector.sh
                                                       └── /api/reports ───▶ analyze.py ◀── SQLite (vulndb.py)
                                                                                              ▲
                                                             Debian Security Tracker · CISA KEV · FIRST EPSS · NVD
```

- **Сбор.** `collect.yml` запускает `collector.sh` модулем `script`, поэтому Python на хостах не нужен. Callback-плагин `amber.py` передаёт прогресс по хостам. Вывод сборщика — текстовые секции, их разбирает `parser.py`.
- **Анализ.** `analyze.py` сопоставляет пакеты с CVE по исходному пакету и версии, определяет уровни и статусы ([правила](vulnerability-assessment.md)) и добавляет находки конфигурации: релиз без поддержки, параметры `sshd`, TLS-сертификаты, заполнение дисков, ожидающая перезагрузка.
- **Базы уязвимостей.** `vulndb.py` загружает данные источников и потоково (ijson) импортирует JSON трекера Debian в SQLite.
- **Состояние.** Отчёты, SSH-ключ и базы уязвимостей хранятся в `AMBER_DATA` ([состав](operations.md#данные)). Состояние выполняющихся сборов и passphrase ключа — в памяти процесса. Поэтому сервис работает в одном экземпляре.
- **Контейнер.** Пользователь UID 10001, PID 1 — `tini`. В Kubernetes `/tmp` и `/home/amber` смонтированы как `emptyDir`, корневая файловая система только для чтения.

## Структура кода

```
app/main.py          FastAPI: страницы, API, аутентификация
app/jobs.py          запуск ansible-playbook в фоне, сборка отчёта
app/scanner.py       nmap, разбор inventory, подготовка ключа
app/parser.py        разбор вывода сборщика
app/analyze.py       сопоставление с CVE, уровни, находки, сводка по парку
app/vulndb.py        загрузка и импорт баз уязвимостей
app/debver.py        сравнение версий Debian (алгоритм dpkg)
app/config.py        настройки из переменных окружения, таблица релизов Debian
app/static/          интерфейс без сборки; шрифты Onest и JetBrains Mono
ansible/             collector.sh, collect.yml, ansible.cfg, callback_plugins/amber.py
deploy/helm/         Helm-чарт
tools/make_demo.py   демонстрационный отчёт
tests/               pytest
.github/             CI, публикация, smoke-тест
```
