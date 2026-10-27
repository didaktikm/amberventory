# Contributing

```bash
python -m venv .venv && . .venv/bin/activate
pip install -r requirements-dev.txt
ruff check .
pytest
shellcheck ansible/collector.sh .github/scripts/*.sh
```

Run the UI with demo data (no fleet needed):

```bash
AMBER_DATA=./data python -m tools.make_demo
AMBER_DATA=./data uvicorn app.main:app --port 8080
```

Chart changes: edit `deploy/helm/amberventory`, run `helm lint` with each `ci/*-values.yaml`, and regenerate
the chart README with `helm-docs --chart-search-root deploy/helm` (CI fails on drift).

Pull requests must pass CI. Keep commits focused; describe the *why* in the message.
