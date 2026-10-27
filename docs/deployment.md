# Развёртывание

Сервис работает в одном экземпляре. Для одиночного запуска см. [быстрый старт](../README.md#быстрый-старт). Перед установкой проверьте [требования](requirements.md).

## Образ

| Тег | Содержимое |
|---|---|
| `X.Y.Z` | релиз |
| `X.Y` | последний патч минорной версии |
| `latest` | последний релиз |
| `edge` | последний коммит `main`, не для рабочих установок |
| `sha-<коммит>` | конкретный коммит `main` |

В рабочих установках указывайте полную версию (`0.1.0`) или digest (`ghcr.io/didaktikm/amberventory@sha256:…`). Пакет в GHCR создаётся приватным: пока он не переведён в public ([releasing.md](releasing.md#публичный-образ)), нужен `docker login ghcr.io` или `imagePullSecrets` в Kubernetes.

## Docker Compose

```bash
git clone https://github.com/didaktikm/amberventory.git && cd amberventory
cp .env.example .env && chmod 600 .env
# задайте AMBER_PASSWORD в .env
docker compose up -d
```

`docker-compose.yml` запускает образ версии `AMBERVENTORY_VERSION` (по умолчанию `0.1.0`) в сети хоста, читает настройки из `.env` и хранит данные в томе `amberventory-data`. Чтобы собрать образ из исходников, выполните `docker compose up -d --build`.

## Reverse proxy

Сервис слушает HTTP на `127.0.0.1:8080`. TLS и публикацию для пользователей выполняет reverse proxy на том же хосте.

Caddy:

```caddyfile
inventory.corp.local {
    reverse_proxy 127.0.0.1:8080
    request_body {
        max_size 128MB
    }
}
```

nginx:

```nginx
server {
    listen 443 ssl;
    server_name inventory.corp.local;
    ssl_certificate     /etc/ssl/certs/inventory.crt;
    ssl_certificate_key /etc/ssl/private/inventory.key;
    client_max_body_size 128m;
    location / {
        proxy_pass http://127.0.0.1:8080;
        proxy_set_header Host $host;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_read_timeout 300s;
    }
}
```

Увеличенный размер тела запроса нужен только для ручной загрузки JSON трекера Debian (около 60 МБ) в изолированном контуре.

## Kubernetes (Helm)

Чарт публикуется как OCI-артефакт. Учётные данные храните в Secret, а параметры — в values-файле под контролем версий:

```bash
kubectl create namespace amberventory
kubectl -n amberventory create secret generic amberventory-credentials \
  --from-literal=username=admin \
  --from-literal=password="$(openssl rand -base64 24)"
```

`values.yaml`:

```yaml
auth:
  existingSecret: amberventory-credentials

ingress:
  enabled: true
  className: nginx
  annotations:
    cert-manager.io/cluster-issuer: corp-ca
  hosts:
    - host: inventory.corp.local
      paths:
        - path: /
          pathType: Prefix
  tls:
    - secretName: amberventory-tls
      hosts: [inventory.corp.local]

networkPolicy:
  enabled: true
  ingressFrom:
    - namespaceSelector:
        matchLabels:
          kubernetes.io/metadata.name: ingress-nginx
```

```bash
helm upgrade --install amberventory oci://ghcr.io/didaktikm/charts/amberventory \
  --version 0.1.0 --namespace amberventory -f values.yaml
helm test amberventory -n amberventory
```

Особенности чарта:

- **Одна реплика, стратегия `Recreate`.** Данные хранятся на одном томе `ReadWriteOnce`; при обновлении под пересоздаётся, данные на PVC сохраняются.
- **Пароль.** Если не заданы ни `auth.password`, ни `auth.existingSecret`, чарт генерирует пароль через `lookup`. В Argo CD, Flux и `helm template` это не работает: пароль будет меняться при каждой отрисовке. Используйте `existingSecret`.
- **Перезапуск при изменении настроек.** Контрольные суммы ConfigMap и Secret вынесены в аннотации пода.
- **Gateway API.** Вместо Ingress можно включить `httpRoute.enabled`.

Все параметры: [справочник чарта](../deploy/helm/amberventory/README.md). Резервное копирование и обновление: [operations.md](operations.md).

## Сеть и сканирование

Сбор по SSH и сканирование nmap выполняются из сетевого окружения сервиса. От этого зависит, какие хосты сервис видит.

| Окружение | Что видит сервис | Когда выбирать |
|---|---|---|
| Docker, `--network host` / `network_mode: host` | сети хоста без NAT | рекомендуемый вариант для Docker |
| Docker, bridge (`-p 127.0.0.1:8080:8080`) | хосты, маршрутизируемые с хоста через NAT; сканирование видит сеть контейнера | если сеть хоста использовать нельзя |
| Kubernetes, сеть подов | хосты, доступные из сети подов кластера | хосты маршрутизируются из кластера |
| Kubernetes, `hostNetwork: true` | сети узла | подсеть доступна с узлов, но не из сети подов |

При `hostNetwork: true` закрепите под на подходящем узле (`nodeSelector`) и ограничьте доступ к порту сервиса на узле: сервис слушает `config.port` на всех интерфейсах узла.

NetworkPolicy (`networkPolicy.enabled`) разрешает входящий трафик только от источников из `networkPolicy.ingressFrom` (пустой список разрешает всех), а исходящий — DNS, порты из `networkPolicy.egress.ports` (по умолчанию 22 и 443) и правила `networkPolicy.egress.extraRules`. Добавьте нестандартные SSH-порты хостов.

## Изолированный контур

Без доступа в интернет базы уязвимостей загружаются одним из способов:

1. **Внутренние зеркала.** Разместите файлы на внутреннем веб-сервере и укажите `AMBER_TRACKER_URL`, `AMBER_KEV_URL`, `AMBER_EPSS_URL` (в чарте `config.trackerUrl`, `config.kevUrl`, `config.epssUrl`). Сервис обновляет базы по расписанию так же, как из интернета.
2. **Ручная загрузка трекера.** Скачайте `https://security-tracker.debian.org/tracker/data/json` на компьютере с доступом в интернет и загрузите файл в интерфейсе: «Базы уязвимостей» → «Нет доступа в интернет?». KEV и EPSS при этом остаются недоступными, уровни определяются только по данным Debian.
3. **Прокси.** Если выход в интернет возможен через прокси, задайте `HTTPS_PROXY` и `NO_PROXY` (в чарте `proxy.https`, `proxy.noProxy`).

CVSS из NVD в изолированном контуре недоступен.
