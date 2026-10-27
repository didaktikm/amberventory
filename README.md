<p align="center">
  <img src="docs/assets/banner.svg?v=2" alt="AmberVentory — Debian fleet inventory & vulnerability report" width="860">
</p>

<p align="center">
  <a href="https://github.com/didaktikm/amberventory/actions/workflows/ci.yml"><img alt="CI" src="https://github.com/didaktikm/amberventory/actions/workflows/ci.yml/badge.svg"></a>
  <a href="LICENSE"><img alt="License: Apache-2.0" src="https://img.shields.io/badge/license-Apache--2.0-E39A1E"></a>
  <img alt="Debian 8–13" src="https://img.shields.io/badge/targets-Debian%208%E2%80%9313-A81D33">
  <img alt="Helm chart" src="https://img.shields.io/badge/helm-chart-0F1689">
  <img alt="Image: amd64 + arm64" src="https://img.shields.io/badge/image-amd64%20%7C%20arm64-1C2330">
</p>

**AmberVentory** — веб-сервис для инвентаризации парка Debian-серверов и оценки уязвимостей. Один контейнер: FastAPI, Ansible (только чтение) и nmap. На целевых машинах ничего устанавливать не нужно — достаточно SSH и bash.

<p align="center">
  <img src="docs/assets/screenshot-start.png?v=2" alt="Стартовая страница" width="49%">
  <img src="docs/assets/screenshot-report.png?v=2" alt="Отчёт" width="49%">
</p>

## Содержание

- [Возможности](#возможности)
- [Быстрый старт](#быстрый-старт)
- [Установка](#установка) — Docker Compose, Kubernetes (Helm)
- [Как пользоваться](#как-пользоваться)
- [Что собирается](#что-собирается)
- [Как оцениваются уязвимости](#как-оцениваются-уязвимости)
- [Ограничения](#ограничения-важно-знать)
- [Безопасность](#безопасность)
- [Конфигурация](#конфигурация)
- [API](#api)
- [Разработка](#разработка)
- [CI/CD и релизы](#cicd-и-релизы)
- [Лицензия](#лицензия)

## Возможности

| | |
|---|---|
| **Два способа добавить хосты** | «Сканировать подсеть» (nmap находит SSH, по баннеру угадывает Debian) или «Использовать inventory» (INI/YAML Ansible: группы, `ansible_host`, `ansible_port`, `ansible_user`, джамп-хосты) |
| **SSH-ключ из интерфейса** | «Загрузить ключ», в том числе с passphrase (хранится только в памяти процесса) |
| **Инвентаризация** | ОС и релиз, ядро, диски и inode (аналог `df -h`), пользователи, службы (системные Debian скрыты; БД, веб, очереди, брокеры, контейнеры выделены), сеть, TLS-сертификаты, пакеты |
| **Уязвимости** | Сопоставление с Debian Security Tracker, пометки CISA KEV и EPSS, CVSS из NVD по запросу. Красный — критично, жёлтый — предупреждение |
| **Отчёты** | Отдельная страница с раскрывающимися деталями, история сохраняется, выгрузка CSV |
| **Без агентов** | Сборщик — один bash-скрипт. Python на целях не нужен, работает и на Debian 8/9 |
| **Production-ready деплой** | Docker Compose и Helm-чарт (non-root, read-only rootfs, NetworkPolicy, Ingress / Gateway API) |

## Быстрый старт

Один контейнер, один том с данными. Пароль задайте свой:

```bash
docker run -d --name amberventory --restart unless-stopped \
  --network host \
  -e AMBER_HOST=127.0.0.1 \
  -e AMBER_PORT=8080 \
  -e AMBER_USER=admin \
  -e AMBER_PASSWORD="$(openssl rand -base64 24)" \
  -v amberventory-data:/data \
  ghcr.io/didaktikm/amberventory:0.1.0
```

Откройте `http://127.0.0.1:8080`. Сгенерированный пароль попадает в переменные контейнера, поэтому его можно посмотреть через `docker inspect amberventory`. Проще сразу записать свой пароль в менеджер паролей и подставить его вместо `$(openssl rand -base64 24)`.

Параметры:

| Параметр | Зачем |
|---|---|
| `--network host` | nmap видит локальную сеть напрямую, без NAT. Для bridge уберите и добавьте `-p 127.0.0.1:8080:8080` (сканирование подсети тогда видит только сеть контейнера) |
| `AMBER_HOST=127.0.0.1` | слушаем только локально; публикуйте через reverse proxy с TLS |
| `AMBER_USER`, `AMBER_PASSWORD` | basic auth. Без них интерфейс открыт всем, кто достучится до порта |
| `-v amberventory-data:/data` | база, отчёты и SSH-ключ. Без тома всё пропадёт при пересоздании контейнера |

Посмотреть интерфейс без реального парка:

```bash
docker exec amberventory python -m tools.make_demo
```

Образ с тегом `0.1.0` появится после публикации релиза. До этого используйте `ghcr.io/didaktikm/amberventory:edge`. Если пакет ещё приватный, `docker pull` потребует `docker login ghcr.io`.

Compose и Kubernetes ниже.

## Установка

### Docker Compose

Поставляемый `docker-compose.yml` использует `network_mode: host`, чтобы nmap видел локальную сеть напрямую, и слушает `127.0.0.1:8080`. Опубликуйте через reverse proxy с TLS, например Caddy:

```
inventory.corp.local {
    reverse_proxy 127.0.0.1:8080
}
```

**Смените пароль `change-me` до первого запуска.** Для bridge-сети уберите `network_mode` и раскомментируйте `ports`.

### Kubernetes (Helm)

Образ и чарт публикуются в GHCR. Чарт — OCI-артефакт:

```bash
helm install amberventory oci://ghcr.io/didaktikm/charts/amberventory \
  --version 0.1.0 --namespace amberventory --create-namespace \
  --set auth.password='<сильный-пароль>' \
  --set ingress.enabled=true \
  --set ingress.className=nginx \
  --set 'ingress.hosts[0].host=inventory.corp.local' \
  --set 'ingress.hosts[0].paths[0].path=/' \
  --set 'ingress.hosts[0].paths[0].pathType=Prefix'
```

Или из исходников: `helm install amberventory deploy/helm/amberventory …`.

Что важно знать до установки:

- **Реплика одна** (`strategy: Recreate`): состояние заданий и passphrase ключа живёт в памяти процесса, база — SQLite на одном RWO-томе. Масштабирование горизонтально не поддерживается.
- **Пароль**: если `auth.password` и `auth.existingSecret` не заданы, чарт генерирует случайный и сохраняет его в Secret (через `lookup`). Это **не работает** при `helm template` и в GitOps (Argo CD, Flux) — там задавайте пароль явно или через `existingSecret`.
- **Образ в GHCR** публикуется как приватный (так устроен GHCR по умолчанию). Workflow `publish.yml` переводит его в public, если в секретах репозитория задан `PACKAGES_TOKEN` (см. [docs/releasing.md](docs/releasing.md)). Без этого нужен `imagePullSecrets` или ручная смена видимости.
- **Сканирование подсети** идёт из пода. Если нужна видимость LAN как с хоста — `--set hostNetwork=true` (и подумайте о NetworkPolicy).
- Контейнер работает от UID 10001, `readOnlyRootFilesystem`, без capabilities, seccomp `RuntimeDefault`.

Полный справочник значений — [`deploy/helm/amberventory/README.md`](deploy/helm/amberventory/README.md), подробности деплоя — [docs/deployment.md](docs/deployment.md).

## Как пользоваться

1. **Хосты.** Введите подсеть (`10.0.0.0/24`) и нажмите «Сканировать подсеть», либо загрузите inventory-файл.
2. **Ключ.** Нажмите «Загрузить ключ» и выберите приватный SSH-ключ. На целях лучше завести отдельного пользователя только для чтения.
3. **Сбор.** Выберите хосты и запустите сбор. Прогресс идёт по каждому хосту.
4. **Отчёт.** Откроется отдельная страница: сводка по парку, хосты, уязвимости с фильтрами, пакеты. Прошлые отчёты сохраняются.
5. **Базы уязвимостей.** Обновляются раз в 6 часов или по кнопке «Обновить». Для изолированных сетей есть ручная загрузка (см. ниже).

## Что собирается

Сборщик — `ansible/collector.sh`, выполняется модулем `script`. На хостах ничего не устанавливается и не меняется (кроме кэша apt, если включить «Обновить списки пакетов»).

| Раздел | Источник |
|---|---|
| ОС, релиз, поддержка | `/etc/os-release`, `/etc/debian_version`, таблица EOL/LTS в `app/config.py` |
| Ядро | `uname -r/-v` (версия пакета запущенного ядра), установленные `linux-image-*`, `/var/run/reboot-required` |
| Диски | `df -PT`, inode, `lsblk` |
| Пользователи | `getent passwd`: root, UID ≥ 1000 и все с login-shell; sudo-группы, число ключей в `authorized_keys`, состояние пароля |
| Службы | `systemctl list-units --state=running`; системные скрыты, остальные по категориям (БД, веб, очереди, контейнеры, мониторинг…) |
| Сеть | `ss -lntup`, Docker-контейнеры, ключевые параметры `sshd -T` |
| Пакеты | `dpkg-query` с исходным пакетом и его версией |
| Обновления | `apt-get -s dist-upgrade` (симуляция) |
| TLS | сертификаты в `/etc/letsencrypt`, nginx, apache2, haproxy, postfix, dovecot, caddy: срок, самоподписанность, SHA-1, короткий ключ |

## Как оцениваются уязвимости

Источники кэшируются в томе:

- **Debian Security Tracker** — какие CVE затрагивают какой исходный пакет в каком релизе и где исправлены. Версии сравниваются по алгоритму `dpkg --compare-versions` (проверено тестами против dpkg).
- **CISA KEV** — CVE, эксплуатируемые в реальных атаках.
- **FIRST EPSS** — вероятность эксплуатации в ближайшие 30 дней.
- **NVD CVSS** — по кнопке в отчёте, только для CVE без оценки Debian. Без `NVD_API_KEY` медленно (~6 с на CVE).

Уровень: urgency из Debian → иначе CVSS из NVD → иначе «без оценки». EPSS ≥ 50% поднимает до «высокого», попадание в KEV — всегда «критично». Ядро оценивается по **запущенной** версии: если исправленное ядро уже установлено, отчёт пишет «нужна перезагрузка».

Статусы: «есть исправление» (и видит ли его apt на хосте), «исправления нет», «отложено Debian» (скрыто по умолчанию).

**Список наблюдения** (`AMBER_WATCHLIST`): openssl, openssh, php\*, sudo, glibc, ядро, nginx, apache2, ca-certificates, gnutls и т.п. подсвечиваются в отчёте. Новые эксплуатируемые CVE приходят через KEV и трекер при обновлении баз автоматически.

**Без интернета:** скачайте `https://security-tracker.debian.org/tracker/data/json` на другой машине и загрузите в блоке «Базы уязвимостей → Нет доступа в интернет?». Либо укажите внутренние зеркала (`AMBER_TRACKER_URL`, `AMBER_KEV_URL`, `AMBER_EPSS_URL`) или `HTTPS_PROXY`.

## Ограничения (важно знать)

- **Сторонние репозитории не покрыты.** Трекер знает только пакеты Debian. PHP из `packages.sury.org`, Docker CE, PostgreSQL из PGDG, nginx mainline помечаются «сторонний / вне трекера», CVE по ним **не сопоставляются**. Это слепая зона: проверяйте такие пакеты отдельно (версии видны в «Пакетах»).
- **Контейнеры не сканируются**, только список запущенных. Для образов используйте Trivy или Grype.
- **Не Debian** (Ubuntu и др.): инвентаризация работает, сопоставление CVE нет (нужны USN).
- **EOL-релизы** (на конец 2026 года Debian 8–11): хост помечается EOL. Если релиза уже нет в трекере, CVE по нему не считаются. Это «неизвестно и не исправляется», а не «чисто».
- Сопоставление по версиям без учёта того, используется ли уязвимая функция. Для «local» CVE на серверах без пользователей ложные срабатывания нормальны, смотрите scope и EPSS.
- Без `apt-get update` список обновлений отражает кэш хоста; отчёт предупреждает, если кэш старше 7 дней.

## Безопасность

Сервис хранит SSH-ключ и строит карту уязвимостей вашей сети — относитесь к нему как к бастиону. Подробнее: [SECURITY.md](SECURITY.md).

- Включите basic auth и TLS на прокси, не публикуйте в интернет.
- Ключ лежит в томе с правами 600; на время задания делается временная расшифрованная копия, удаляется сразу после. Ключ можно удалить из интерфейса.
- По умолчанию host key **не проверяется** (иначе первый запуск по новой подсети упадёт). Для строгого режима смонтируйте `known_hosts` (`knownHosts` в чарте) и включите «Проверять host key».
- Username для SSH валидируется, цели сканирования ограничены `AMBER_MAX_SCAN_HOSTS`.

## Конфигурация

| Переменная | По умолчанию | Назначение |
|---|---|---|
| `AMBER_HOST`, `AMBER_PORT` | `0.0.0.0`, `8080` | адрес веб-интерфейса |
| `AMBER_USER`, `AMBER_PASSWORD` | пусто | basic auth (пусто — выключено) |
| `AMBER_DATA` | `/data` | каталог данных (SQLite, ключ, отчёты) |
| `AMBER_FORKS` | `25` | параллельных SSH-сессий |
| `AMBER_SSH_TIMEOUT` | `15` | таймаут подключения, с |
| `AMBER_JOB_TIMEOUT` | `1800` | лимит на задание, с |
| `AMBER_MAX_SCAN_HOSTS` | `4096` | лимит адресов для nmap |
| `AMBER_FEED_TTL` | `21600` | период обновления баз, с |
| `AMBER_NVD_MAX` | `300` | максимум CVE для запроса в NVD за запуск |
| `AMBER_WATCHLIST` | см. `app/config.py` | пакеты под наблюдением, glob через запятую |
| `NVD_API_KEY` | пусто | ускоряет загрузку CVSS |
| `AMBER_TRACKER_URL`, `AMBER_KEV_URL`, `AMBER_EPSS_URL` | официальные | зеркала фидов |

В Helm-чарте это `config.*`, `auth.*`, `nvd.*`, `proxy.*` ([справочник](deploy/helm/amberventory/README.md)). Значения по умолчанию чарта отличаются от приложения в одном месте: `config.forks=10`.

## API

Swagger: `/api/docs`. Основное: `POST /api/scan`, `POST /api/inventory`, `POST /api/key`, `POST /api/jobs`, `GET /api/jobs/{id}`, `GET /api/reports/{id}`, `GET /api/reports/{id}/vulns.csv`, `POST /api/reports/{id}/reanalyze`. `GET /healthz` — без авторизации.

## Разработка

```
app/main.py        FastAPI: страницы, API, basic auth
app/jobs.py        фоновый запуск ansible-playbook, сборка отчёта
app/parser.py      разбор вывода сборщика
app/vulndb.py      загрузка и импорт фидов в SQLite (потоково)
app/analyze.py     сопоставление пакетов с CVE, уровни, находки, сводка по парку
app/debver.py      сравнение версий Debian
app/static/        интерфейс без сборки (шрифты Onest и JetBrains Mono локально)
ansible/           collector.sh + collect.yml + callback_plugins/amber.py
deploy/helm/       Helm-чарт
tools/make_demo.py демо-отчёт
tests/             pytest (debver, parser, analyze, API)
```

```bash
pip install -r requirements-dev.txt
ruff check . && pytest
```

См. [CONTRIBUTING.md](CONTRIBUTING.md). Архитектура: [docs/architecture.md](docs/architecture.md).

## CI/CD и релизы

- `ci.yml` — на каждый PR и push в `main`: ruff, shellcheck, pytest; `ct lint`, валидация чарта (kubeconform) и проверка актуальности README чарта; e2e: сборка образа, установка чарта в kind, `helm test` и smoke-тест (включая nmap и разбор inventory при read-only rootfs).
- `publish.yml` — после успешного CI: образ `ghcr.io/didaktikm/amberventory` (amd64+arm64, SBOM, provenance, отчёт Trivy). Теги: `edge` и `sha-…` для `main`; `X.Y.Z`, `X.Y`, `latest` для тега `vX.Y.Z`. На тег дополнительно публикуются чарт `oci://ghcr.io/didaktikm/charts/amberventory` и GitHub Release.

Выпуск: `git tag v0.2.0 && git push origin v0.2.0`. Подробнее: [docs/releasing.md](docs/releasing.md).

## Лицензия

[Apache License 2.0](LICENSE). Сторонние компоненты и их лицензии — в [NOTICE](NOTICE). Образ содержит nmap (NPSL) и запускает ansible-core (GPL-3.0) как отдельные процессы; при распространении образа учтите их условия.
