# Участие в разработке

## Окружение

Нужны Python 3.11+, nmap и ansible-core (ставится из `requirements.txt`).

```bash
python -m venv .venv && . .venv/bin/activate
pip install -r requirements-dev.txt
```

Запуск интерфейса на демонстрационных данных:

```bash
AMBER_DATA=./data python -m tools.make_demo
AMBER_DATA=./data uvicorn app.main:app --port 8080
```

Структура кода: [docs/architecture.md](docs/architecture.md).

## Проверки

Те же проверки выполняет CI для каждого pull request:

```bash
ruff check .
pytest
shellcheck ansible/collector.sh .github/scripts/*.sh
```

Изменения Helm-чарта:

```bash
for f in deploy/helm/amberventory/ci/*-values.yaml; do helm lint deploy/helm/amberventory -f "$f"; done
helm-docs --chart-search-root deploy/helm   # README чарта генерируется из values.yaml
```

CI завершается ошибкой, если README чарта не соответствует `values.yaml`.

## Требования к изменениям

- Pull request проходит CI.
- Изменение поведения сопровождается тестом.
- Изменения, заметные пользователю, описаны в разделе «Не выпущено» в [CHANGELOG.md](CHANGELOG.md).
- Документация обновлена в том же pull request; термины — по [словарю](docs/glossary.md).
- Изменения сборщика (`ansible/collector.sh`), которые добавляют вызовы через `sudo`, отражены в [списке команд sudo](docs/requirements.md#ограниченный-sudo).
- Сообщение коммита объясняет, зачем сделано изменение.

## CI и релизы

| Workflow | Когда | Что делает |
|---|---|---|
| `ci.yml` | pull request, push в `main` | ruff, shellcheck, pytest; `ct lint`, проверка манифестов kubeconform, актуальность README чарта; сборка образа, установка чарта в kind, `helm test`, smoke-тест |
| `publish.yml` | push в `main`, тег `v*.*.*` | CI, образ в GHCR; для тега — чарт в GHCR и GitHub Release |

Выпуск версии: [docs/releasing.md](docs/releasing.md).
