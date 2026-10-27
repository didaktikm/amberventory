# amberventory

![Version: 0.1.0](https://img.shields.io/badge/Version-0.1.0-informational?style=flat-square) ![Type: application](https://img.shields.io/badge/Type-application-informational?style=flat-square) ![AppVersion: 0.1.0](https://img.shields.io/badge/AppVersion-0.1.0-informational?style=flat-square)

Helm-чарт сервиса AmberVentory: инвентаризация парка Debian и оценка уязвимостей.

**Homepage:** <https://github.com/didaktikm/amberventory>

Общая документация сервиса: [README](https://github.com/didaktikm/amberventory#readme), развёртывание — [docs/deployment.md](https://github.com/didaktikm/amberventory/blob/main/docs/deployment.md).

## Требования

- Kubernetes >=1.25.0-0
- Helm 3.8+ (поддержка OCI) или Helm 4
- StorageClass с томами `ReadWriteOnce` или готовый PVC (`persistence.existingClaim`)
- Сетевой доступ из пода к хостам по SSH и к источникам баз уязвимостей по HTTPS (или к их внутренним зеркалам): [перечень адресов](https://github.com/didaktikm/amberventory/blob/main/docs/requirements.md#сеть)

## Установка

Учётные данные храните в Secret, параметры — в values-файле:

```bash
kubectl create namespace amberventory
kubectl -n amberventory create secret generic amberventory-credentials \
  --from-literal=username=admin \
  --from-literal=password="$(openssl rand -base64 24)"

helm upgrade --install amberventory oci://ghcr.io/didaktikm/charts/amberventory \
  --version 0.1.0 --namespace amberventory \
  --set auth.existingSecret=amberventory-credentials
helm test amberventory -n amberventory
```

Доступ без Ingress, для проверки:

```bash
kubectl -n amberventory port-forward svc/amberventory 8080:80
```

## Принятые решения

| Решение | Причина |
|---|---|
| **Одна реплика, стратегия `Recreate`** | Состояние выполняющихся сборов и passphrase SSH-ключа хранятся в памяти процесса, данные — в SQLite на одном томе. Вторая реплика не увидит это состояние, а rolling update попытается смонтировать том `ReadWriteOnce` дважды. Поэтому в чарте нет `replicaCount`, HPA и PodDisruptionBudget. |
| **Аутентификация включена по умолчанию** | Сервис хранит SSH-ключ с доступом ко всем хостам. Если не заданы `auth.password` и `auth.existingSecret`, чарт генерирует случайный пароль. При отключении аутентификации NOTES выводят предупреждение. |
| **Усиленная конфигурация пода** | Непривилегированный пользователь (UID 10001), корневая файловая система только для чтения, сброшены все capabilities, профиль seccomp `RuntimeDefault`, токен ServiceAccount не монтируется. Каталоги `/data`, `/tmp` и `/home/amber` — тома. nmap без привилегий использует TCP connect scan, этого достаточно для поиска SSH. |
| **Перезапуск при изменении настроек** | Контрольные суммы ConfigMap и Secret вынесены в аннотации пода. |
| **Gateway API как опция** | `httpRoute.enabled` создаёт `HTTPRoute` вместо Ingress. |

## Типовые задачи

### Ingress с TLS

```yaml
ingress:
  enabled: true
  className: nginx
  annotations:
    cert-manager.io/cluster-issuer: corp-ca
    # Только для ручной загрузки JSON трекера Debian (около 60 МБ) в изолированном контуре
    nginx.ingress.kubernetes.io/proxy-body-size: 128m
  hosts:
    - host: inventory.corp.local
      paths:
        - path: /
          pathType: Prefix
  tls:
    - secretName: amberventory-tls
      hosts:
        - inventory.corp.local
```

### Argo CD, Flux и `helm template`

Задавайте `auth.existingSecret` или `auth.password`. Автогенерация пароля использует `lookup`, который в этих инструментах не работает: пароль будет меняться при каждой отрисовке.

### Подсеть недоступна из сети подов

Запустите под в сети узла и закрепите его на узле с доступом к нужной подсети:

```yaml
hostNetwork: true
nodeSelector:
  kubernetes.io/hostname: node-in-the-right-vlan
```

Сервис будет слушать `config.port` на всех интерфейсах узла: ограничьте доступ к порту межсетевым экраном.

### Ограничение сетевого доступа

```yaml
networkPolicy:
  enabled: true
  ingressFrom:
    - namespaceSelector:
        matchLabels:
          kubernetes.io/metadata.name: ingress-nginx
  egress:
    ports: [22, 443]   # добавьте нестандартные SSH-порты хостов
```

### Приватный реестр или приватный пакет GHCR

Пакет в GitHub Container Registry приватный, пока его видимость не изменена. Создайте секрет для загрузки образа:

```bash
kubectl -n amberventory create secret docker-registry ghcr \
  --docker-server=ghcr.io --docker-username=<пользователь> --docker-password=<токен с read:packages>
helm upgrade --install amberventory ... --set 'imagePullSecrets[0].name=ghcr'
```

### Проверка ключей хостов

Передайте ключи хостов, полученные доверенным способом, и включите «Проверять host key» при запуске сбора:

```yaml
knownHosts: |
  10.0.0.11 ssh-ed25519 AAAA...
  10.0.0.12 ssh-ed25519 AAAA...
```

### SSH-ключ

Ключ загружается через веб-интерфейс и хранится в `/data/keys` на постоянном томе с правами 600. В параметры чарта он не входит. Без постоянного тома ключ придётся загружать после каждого перезапуска.

## Обновление, проверка, удаление

```bash
helm upgrade amberventory oci://ghcr.io/didaktikm/charts/amberventory --version <версия> -n amberventory -f values.yaml
helm test amberventory -n amberventory       # запрос /healthz изнутри кластера
helm uninstall amberventory -n amberventory  # PVC удаляется, если нет аннотации helm.sh/resource-policy: keep
```

Резервное копирование и откат: [docs/operations.md](https://github.com/didaktikm/amberventory/blob/main/docs/operations.md).

## Параметры

| Параметр | Тип | По умолчанию | Описание |
|----------|-----|--------------|----------|
| affinity | object | `{}` | Правила affinity |
| auth.enabled | bool | `true` | Включить HTTP basic auth (`/healthz` остаётся открытым для проб) |
| auth.existingSecret | string | `""` | Имя существующего Secret с учётными данными |
| auth.existingSecretPasswordKey | string | `"password"` | Ключ с паролем в `existingSecret` |
| auth.existingSecretUserKey | string | `"username"` | Ключ с именем пользователя в `existingSecret` |
| auth.password | string | `""` | Пароль. Если пусто, при первой установке генерируется случайный и сохраняется при обновлениях (только для `helm install/upgrade`; для `helm template` и GitOps задайте значение или `existingSecret`) |
| auth.username | string | `"admin"` | Имя пользователя. Не используется, если задан `existingSecret` |
| commonAnnotations | object | `{}` | Аннотации для всех ресурсов |
| commonLabels | object | `{}` | Метки для всех ресурсов |
| config.epssUrl | string | `""` | Зеркала файла EPSS через запятую (`AMBER_EPSS_URL`) |
| config.feedTtl | int | `21600` | Интервал обновления баз уязвимостей, с (`AMBER_FEED_TTL`) |
| config.forks | int | `10` | Число параллельных SSH-сессий (`AMBER_FORKS`). Каждая сессия — отдельный процесс Python (оценка: 50–80 MiB), согласуйте с лимитом памяти |
| config.jobTimeout | int | `1800` | Максимальная длительность одного сбора, с (`AMBER_JOB_TIMEOUT`) |
| config.kevUrl | string | `""` | Зеркало каталога CISA KEV (`AMBER_KEV_URL`) |
| config.maxScanHosts | int | `4096` | Максимум адресов в одном запросе на сканирование (`AMBER_MAX_SCAN_HOSTS`) |
| config.nvdMaxPerRun | int | `300` | Максимум CVE, запрашиваемых в NVD за один запуск (`AMBER_NVD_MAX`) |
| config.port | int | `8080` | Порт, на котором слушает сервис |
| config.sshTimeout | int | `15` | Таймаут SSH-подключения, с (`AMBER_SSH_TIMEOUT`) |
| config.trackerUrl | string | `""` | Зеркало JSON Debian Security Tracker (`AMBER_TRACKER_URL`) |
| config.watchlist | string | `""` | Список наблюдения: исходные пакеты Debian, glob через запятую (`AMBER_WATCHLIST`). Пусто — встроенный список |
| dnsPolicy | string | `""` | Политика DNS. При `hostNetwork: true` и пустом значении используется `ClusterFirstWithHostNet` |
| extraEnv | list | `[]` | Дополнительные переменные окружения (список `EnvVar`) |
| extraEnvFrom | list | `[]` | Дополнительные источники `envFrom` (ConfigMap или Secret) |
| extraVolumeMounts | list | `[]` | Дополнительные точки монтирования в контейнере |
| extraVolumes | list | `[]` | Дополнительные тома |
| fullnameOverride | string | `""` | Заменяет полное имя ресурсов |
| hostNetwork | bool | `false` | Запускать под в сети узла. Нужно, если подсеть доступна с узлов, но не из сети подов |
| httpRoute.annotations | object | `{}` | Аннотации HTTPRoute |
| httpRoute.enabled | bool | `false` | Создать HTTPRoute (Gateway API) |
| httpRoute.hostnames | list | `[]` | Имена хостов маршрута |
| httpRoute.parentRefs | list | `[]` | Gateway, к которым подключается маршрут |
| httpRoute.rules | list | `[]` | Правила маршрута. По умолчанию `/` направляется в Service |
| image.digest | string | `""` | Digest образа (`sha256:...`). Если задан, используется вместо `tag` |
| image.pullPolicy | string | `"IfNotPresent"` | Политика загрузки образа |
| image.repository | string | `"ghcr.io/didaktikm/amberventory"` | Репозиторий образа |
| image.tag | string | `""` | Тег образа. По умолчанию `appVersion` чарта |
| imagePullSecrets | list | `[]` | Секреты для загрузки образа из приватного реестра. Новый пакет в GitHub Container Registry приватный, пока его видимость не изменена |
| ingress.annotations | object | `{}` | Аннотации Ingress. Для ручной загрузки JSON трекера Debian (около 60 МБ) увеличьте лимит тела запроса, например `nginx.ingress.kubernetes.io/proxy-body-size: 128m` |
| ingress.className | string | `""` | Имя IngressClass |
| ingress.enabled | bool | `false` | Создать Ingress |
| ingress.hosts | list | `[{"host":"amberventory.example.com","paths":[{"path":"/","pathType":"Prefix"}]}]` | Хосты и пути Ingress |
| ingress.tls | list | `[]` | Настройки TLS для Ingress |
| knownHosts | string | `""` | Содержимое `known_hosts`, монтируется в `~/.ssh/known_hosts`. Нужно для режима «Проверять host key» |
| livenessProbe.enabled | bool | `true` | Включить liveness-пробу |
| livenessProbe.failureThreshold | int | `3` | Число неудачных проверок до перезапуска контейнера |
| livenessProbe.httpGet.path | string | `"/healthz"` | HTTP-путь liveness-пробы |
| livenessProbe.httpGet.port | string | `"http"` | Порт liveness-пробы (имя порта контейнера) |
| livenessProbe.periodSeconds | int | `20` | Период liveness-пробы, с |
| livenessProbe.timeoutSeconds | int | `5` | Таймаут liveness-пробы, с |
| nameOverride | string | `""` | Заменяет имя чарта в именах ресурсов |
| networkPolicy.egress.dns | bool | `true` | Разрешить DNS-запросы (порт 53 TCP/UDP) к любым адресам |
| networkPolicy.egress.extraRules | list | `[]` | Дополнительные правила исходящего трафика (список NetworkPolicyEgressRule) |
| networkPolicy.egress.ports | list | `[22,443]` | TCP-порты, разрешённые к любым адресам: SSH к хостам, HTTPS к источникам баз уязвимостей. Добавьте нестандартные SSH-порты |
| networkPolicy.enabled | bool | `false` | Создать NetworkPolicy |
| networkPolicy.ingressFrom | list | `[]` | Источники, которым разрешён доступ к сервису (список NetworkPolicyPeer). Пусто — разрешены все |
| nodeSelector | object | `{}` | Селектор узлов |
| nvd.apiKey | string | `""` | Ключ API NVD. Необязательный: ускоряет загрузку CVSS примерно в десять раз |
| nvd.existingSecret | string | `""` | Имя существующего Secret с ключом API NVD |
| nvd.existingSecretKey | string | `"api-key"` | Ключ с ключом API в `existingSecret` |
| persistence.accessModes | list | `["ReadWriteOnce"]` | Режимы доступа. Сервис работает в одной реплике, `ReadWriteOnce` достаточно |
| persistence.annotations | object | `{}` | Аннотации PVC. `helm.sh/resource-policy: keep` сохраняет том после `helm uninstall` |
| persistence.enabled | bool | `true` | Хранить `/data` (SSH-ключ, отчёты, базы уязвимостей) на постоянном томе. Если выключено, используется `emptyDir` и данные теряются при перезапуске |
| persistence.existingClaim | string | `""` | Использовать существующий PersistentVolumeClaim |
| persistence.size | string | `"5Gi"` | Размер тома |
| persistence.storageClass | string | `""` | StorageClass. `-` отключает динамическое выделение, пусто — класс кластера по умолчанию |
| podAnnotations | object | `{}` | Аннотации пода |
| podLabels | object | `{}` | Метки пода |
| podSecurityContext | object | `{"fsGroup":10001,"fsGroupChangePolicy":"OnRootMismatch","runAsGroup":10001,"runAsNonRoot":true,"runAsUser":10001,"seccompProfile":{"type":"RuntimeDefault"}}` | Контекст безопасности пода. UID/GID 10001 — пользователь `amber` из образа |
| priorityClassName | string | `""` | Имя PriorityClass |
| proxy.http | string | `""` | `HTTP_PROXY` для загрузки баз уязвимостей. Учётные данные прокси передавайте через `extraEnvFrom` из Secret, не здесь |
| proxy.https | string | `""` | `HTTPS_PROXY` для загрузки баз уязвимостей |
| proxy.noProxy | string | `""` | `NO_PROXY` |
| readinessProbe.enabled | bool | `true` | Включить readiness-пробу |
| readinessProbe.failureThreshold | int | `3` | Число неудачных проверок до исключения пода из Service |
| readinessProbe.httpGet.path | string | `"/healthz"` | HTTP-путь readiness-пробы |
| readinessProbe.httpGet.port | string | `"http"` | Порт readiness-пробы (имя порта контейнера) |
| readinessProbe.periodSeconds | int | `10` | Период readiness-пробы, с |
| readinessProbe.timeoutSeconds | int | `5` | Таймаут readiness-пробы, с |
| resources | object | `{"limits":{"memory":"2Gi"},"requests":{"cpu":"100m","memory":"512Mi"}}` | Запросы и лимиты ресурсов. Это оценки, а не замеры: память растёт с `config.forks` и размером парка |
| securityContext | object | `{"allowPrivilegeEscalation":false,"capabilities":{"drop":["ALL"]},"readOnlyRootFilesystem":true}` | Контекст безопасности контейнера. Каталоги для записи (`/data`, `/tmp`, `/home/amber`) смонтированы как тома |
| service.annotations | object | `{}` | Аннотации Service |
| service.nodePort | string | `nil` | Порт узла для `type: NodePort` |
| service.port | int | `80` | Порт Service |
| service.type | string | `"ClusterIP"` | Тип Service |
| serviceAccount.annotations | object | `{}` | Аннотации ServiceAccount |
| serviceAccount.automount | bool | `false` | Монтировать токен ServiceAccount. Сервис не обращается к Kubernetes API |
| serviceAccount.create | bool | `true` | Создать ServiceAccount |
| serviceAccount.name | string | `""` | Имя ServiceAccount. Если пусто, формируется из имени релиза |
| startupProbe.enabled | bool | `true` | Включить startup-пробу |
| startupProbe.failureThreshold | int | `30` | Число неудачных проверок до перезапуска контейнера |
| startupProbe.httpGet.path | string | `"/healthz"` | HTTP-путь startup-пробы |
| startupProbe.httpGet.port | string | `"http"` | Порт startup-пробы (имя порта контейнера) |
| startupProbe.periodSeconds | int | `5` | Период startup-пробы, с |
| terminationGracePeriodSeconds | int | `30` | Время на корректное завершение пода, с |
| tolerations | list | `[]` | Tolerations |

Файл сгенерирован [helm-docs](https://github.com/norwoodj/helm-docs) из `values.yaml` и `README.md.gotmpl`; правьте их, а не этот файл.
