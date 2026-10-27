# Развёртывание

## Docker Compose
См. [README](../README.md#docker-compose). Данные — в томе `amber-data`. Бэкап: `docker run --rm -v amber-data:/d -v $PWD:/b busybox tar czf /b/amber-data.tgz -C /d .`

## Helm
Чарт: `deploy/helm/amberventory`, значения и описания — в [README чарта](../deploy/helm/amberventory/README.md).

### Пароль
| Способ | Как |
|---|---|
| Явно | `--set auth.password=…` (попадёт в историю релиза Helm) |
| Свой Secret | `--set auth.existingSecret=my-secret` (ключи по умолчанию `username`, `password`; настраиваются) |
| Автогенерация | по умолчанию; читается через `kubectl get secret … -o jsonpath='{.data.password}' \| base64 -d`. Не работает в `helm template` и GitOps |

### Ingress и TLS
```yaml
ingress:
  enabled: true
  className: nginx
  annotations: { cert-manager.io/cluster-issuer: letsencrypt }
  hosts:
    - host: inventory.corp.local
      paths: [{ path: /, pathType: Prefix }]
  tls:
    - secretName: inventory-tls
      hosts: [inventory.corp.local]
```
Вместо Ingress можно включить `httpRoute.enabled` (Gateway API).

### Сеть
Сканирование и SSH идут из пода. `networkPolicy.enabled=true` разрешает входящий трафик только из `ingressFrom`, исходящий — DNS, порты 22 и 443 (фиды) и `extraRules`. Для nmap по LAN как с хоста: `hostNetwork=true`.

### Проверка
```bash
helm test amberventory -n amberventory
```

### Обновление и откат
`helm upgrade …` пересоздаёт под (Recreate), данные на PVC сохраняются. Изменение ConfigMap/Secret вызывает перезапуск через checksum-аннотации. Откат: `helm rollback`.

## Образ
`ghcr.io/didaktikm/amberventory:<версия>`; закрепить по digest: `image.digest=sha256:…`. Пакет в GHCR создаётся приватным — измените видимость или используйте `imagePullSecrets`.
