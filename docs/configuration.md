# Настройка

Сервис настраивается переменными окружения. В Docker их удобно хранить в файле для `--env-file` или `env_file` (шаблон — [`.env.example`](../.env.example)). В Helm-чарте те же настройки задаются параметрами, и чарт превращает их в переменные.

| Переменная | По умолчанию | Параметр чарта | Назначение |
|---|---|---|---|
| `AMBER_HOST` | `0.0.0.0` | — (всегда `0.0.0.0`) | адрес, на котором слушает веб-интерфейс |
| `AMBER_PORT` | `8080` | `config.port` | порт веб-интерфейса |
| `AMBER_USER` | пусто | `auth.username` или `auth.existingSecret` | имя пользователя basic auth |
| `AMBER_PASSWORD` | пусто | `auth.password` или `auth.existingSecret` | пароль basic auth; пустое значение отключает аутентификацию (в чарте её отключает `auth.enabled: false`) |
| `AMBER_DATA` | `/data` | — (всегда `/data` на PVC) | каталог данных |
| `AMBER_FORKS` | `25` | `config.forks` (по умолчанию `10`) | число параллельных SSH-сессий при сборе |
| `AMBER_SSH_TIMEOUT` | `15` | `config.sshTimeout` | таймаут SSH-подключения, с |
| `AMBER_JOB_TIMEOUT` | `1800` | `config.jobTimeout` | максимальная длительность одного сбора, с |
| `AMBER_MAX_SCAN_HOSTS` | `4096` | `config.maxScanHosts` | максимум адресов в одном запросе на сканирование |
| `AMBER_FEED_TTL` | `21600` | `config.feedTtl` | интервал автоматического обновления баз уязвимостей, с |
| `AMBER_NVD_MAX` | `300` | `config.nvdMaxPerRun` | максимум CVE, запрашиваемых в NVD за один запуск |
| `AMBER_WATCHLIST` | встроенный список | `config.watchlist` | пакеты под наблюдением: исходные пакеты Debian, glob через запятую |
| `NVD_API_KEY` | пусто | `nvd.apiKey` или `nvd.existingSecret` | ключ API NVD; без ключа NVD ограничивает частоту запросов |
| `AMBER_TRACKER_URL` | `https://security-tracker.debian.org/tracker/data/json` | `config.trackerUrl` | источник Debian Security Tracker |
| `AMBER_KEV_URL` | каталог CISA KEV на `www.cisa.gov` | `config.kevUrl` | источник CISA KEV |
| `AMBER_EPSS_URL` | `epss.empiricalsecurity.com`, резервный `epss.cyentia.com` | `config.epssUrl` | источники EPSS через запятую, используются по порядку |
| `HTTP_PROXY`, `HTTPS_PROXY`, `NO_PROXY` | пусто | `proxy.http`, `proxy.https`, `proxy.noProxy` | прокси для загрузки баз уязвимостей |

Встроенный список наблюдения и таблица релизов Debian находятся в `app/config.py`.

Дополнительные переменные в чарте передаются через `extraEnv` и `extraEnvFrom`. Учётные данные прокси передавайте через `extraEnvFrom` из Secret, а не через `proxy.*`: значения `proxy.*` попадают в ConfigMap.

## Настройки в интерфейсе

Часть параметров задаётся при запуске сбора и не хранится в конфигурации:

| Параметр | Назначение |
|---|---|
| Пользователь SSH | учётная запись на хостах, если она не задана в inventory (`ansible_user`) |
| Запускать сборщик целиком через sudo | выполнить весь сборщик с правами root через `sudo`; требует sudo без пароля на любые команды. Без опции используется ограниченный sudo ([requirements.md](requirements.md#что-требует-повышенных-прав)) |
| Обновить списки пакетов | выполнить `apt-get update` перед проверкой обновлений; требует прав ([requirements.md](requirements.md#доступ-к-хостам)) |
| Проверять host key | сверять ключи хостов с `known_hosts` ([security.md](security.md#проверка-ключей-хостов)) |
