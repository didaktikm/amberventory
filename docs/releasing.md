# Релизы

1. Убедитесь, что `main` зелёный (workflow **CI**).
2. `git tag v0.2.0 && git push origin v0.2.0`.
3. Workflow **Publish** прогонит CI, соберёт мультиархитектурный образ, опубликует чарт версии `0.2.0` (версия и appVersion берутся из тега) и создаст GitHub Release.

Результаты: образ `ghcr.io/didaktikm/amberventory:0.2.0` (`0.2`, `latest`), чарт `oci://ghcr.io/didaktikm/charts/amberventory --version 0.2.0`. Теги с дефисом (`v0.2.0-rc.1`) помечаются как pre-release.

## Публичный образ (`docker pull` без логина)

GHCR создаёт пакет приватным, а `GITHUB_TOKEN` не может менять его видимость. Два варианта:

1. **Автоматически.** Создайте персональный токен (classic с `write:packages`, либо fine-grained с правом Packages: read and write) и сохраните его как секрет репозитория `PACKAGES_TOKEN` (Settings → Secrets and variables → Actions). Job `make-public` в `publish.yml` будет переводить пакет в public на каждой публикации.
2. **Вручную, один раз.** Packages → `amberventory` → Package settings → Change visibility → Public. Настройка сохраняется для следующих публикаций.

Проверка: `docker logout ghcr.io && docker pull ghcr.io/didaktikm/amberventory:latest`.

Версии GitHub Actions закреплены мажорными тегами; обновления приходят через Dependabot.
