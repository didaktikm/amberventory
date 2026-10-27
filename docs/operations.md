# Эксплуатация

## Данные

Все данные сервиса находятся в каталоге `AMBER_DATA` (`/data` в контейнере):

| Путь | Содержимое | Ценность для восстановления |
|---|---|---|
| `keys/` | загруженный SSH-ключ (права `600`) | высокая; ключ можно загрузить заново из хранилища секретов |
| `reports/` | отчёты | высокая, другого источника нет |
| `jobs/` | рабочие файлы сборов (параметры и вывод сборщика) | средняя: нужны для пересчёта отчёта |
| `inventories/` | загруженные inventory | низкая |
| `vulndb.sqlite`, `feeds/` | базы уязвимостей | низкая: загружаются заново из источников |
| `demo-feeds/` | синтетические базы демонстрационного режима | нет |

Passphrase SSH-ключа хранится только в памяти процесса. После перезапуска сервиса её нужно ввести заново.

## Резервное копирование

Останавливайте сервис на время копирования: SQLite и отчёты записываются во время сбора, и копия работающего тома может оказаться несогласованной.

Docker:

```bash
docker stop amberventory
docker run --rm -v amberventory-data:/data:ro -v "$PWD":/backup busybox \
  tar czf /backup/amberventory-$(date +%F).tgz -C /data .
docker start amberventory
```

Восстановление:

```bash
docker stop amberventory
docker run --rm -v amberventory-data:/data -v "$PWD":/backup busybox \
  tar xzf /backup/amberventory-YYYY-MM-DD.tgz -C /data
docker start amberventory
```

Kubernetes: используйте снимки тома (VolumeSnapshot) средствами CSI-драйвера или Velero. Для согласованного снимка временно остановите под (`kubectl -n amberventory scale deploy/amberventory --replicas=0`; следующий `helm upgrade` вернёт одну реплику). Чтобы восстановиться, создайте PVC из снимка и укажите его в `persistence.existingClaim`.

Архив содержит SSH-ключ: храните резервные копии с тем же уровнем защиты, что и сам ключ.

## Обновление

Перед обновлением прочитайте [CHANGELOG.md](../CHANGELOG.md) и сделайте резервную копию. До версии 1.0 формат данных может меняться между минорными версиями; такие изменения отмечаются в CHANGELOG.

Docker:

```bash
docker pull ghcr.io/didaktikm/amberventory:0.1.1
docker rm -f amberventory
# повторите docker run из README с новой версией
```

Docker Compose: измените `AMBERVENTORY_VERSION` в `.env` и выполните `docker compose up -d`.

Kubernetes:

```bash
helm upgrade amberventory oci://ghcr.io/didaktikm/charts/amberventory \
  --version 0.1.1 -n amberventory -f values.yaml
helm test amberventory -n amberventory
```

Откат: `helm rollback amberventory -n amberventory`. Если новая версия успела изменить формат данных, откатывайте вместе с восстановлением тома из резервной копии.

## Хранение отчётов

Автоматической очистки нет: отчёты накапливаются, пока их не удалят в интерфейсе или через `DELETE /api/reports/{id}`. Контролируйте заполнение тома и удаляйте устаревшие отчёты в соответствии с принятым сроком хранения.

## Журналы

Сервис пишет журнал в stdout контейнера: события приложения в формате `время уровень логгер: сообщение` и журнал HTTP-запросов uvicorn. Журнал запросов не содержит имени пользователя, поэтому не заменяет журнал действий. Подробный вывод каждого сбора хранится в `jobs/<id>/`.

Собирайте stdout штатными средствами платформы (Docker logging driver, сборщик логов кластера).

## Мониторинг

| Что контролировать | Как |
|---|---|
| Живость сервиса | `GET /healthz` (без аутентификации); `HEALTHCHECK` в образе; startup, liveness и readiness-пробы в чарте |
| Перезапуски | счётчик рестартов контейнера или пода |
| Заполнение тома | метрики тома платформы |
| Актуальность баз уязвимостей | дата обновления баз в шапке интерфейса и в `GET /api/state` (`vulndb.*_imported`) |

Метрик Prometheus сервис не публикует.

## Демонстрационные данные

Демонстрационный режим создаёт отчёт по синтетическим хостам и CVE (`CVE-2099-*`, пометка `[DEMO]`). Запускайте его в отдельном контейнере с отдельным томом, чтобы не смешивать с рабочими отчётами:

```bash
docker run -d --name amberventory-demo -p 127.0.0.1:8081:8080 \
  -v amberventory-demo:/data ghcr.io/didaktikm/amberventory:0.1.0
docker exec amberventory-demo python -m tools.make_demo
# http://127.0.0.1:8081
docker rm -f amberventory-demo && docker volume rm amberventory-demo
```

## Удаление

Docker: `docker rm -f amberventory && docker volume rm amberventory-data`.

Kubernetes: `helm uninstall amberventory -n amberventory`. PVC удаляется вместе с релизом, если у него нет аннотации `helm.sh/resource-policy: keep` (задаётся через `persistence.annotations`).
