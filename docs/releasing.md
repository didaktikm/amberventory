# Релизы

1. Убедитесь, что `main` зелёный (workflow **CI**).
2. `git tag v0.2.0 && git push origin v0.2.0`.
3. Workflow **Publish** прогонит CI, соберёт мультиархитектурный образ, опубликует чарт версии `0.2.0` (версия и appVersion берутся из тега) и создаст GitHub Release.

Результаты: образ `ghcr.io/didaktikm/amberventory:0.2.0` (`0.2`, `latest`), чарт `oci://ghcr.io/didaktikm/charts/amberventory --version 0.2.0`. Теги с дефисом (`v0.2.0-rc.1`) помечаются как pre-release.

Первый раз: Settings → Actions → General → Workflow permissions должны разрешать запись пакетов (достаточно `permissions:` в workflow), затем смените видимость пакетов на public, если нужен анонимный pull.

Версии GitHub Actions закреплены мажорными тегами; обновления приходят через Dependabot.
