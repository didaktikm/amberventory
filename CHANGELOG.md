# История изменений

Формат — [Keep a Changelog](https://keepachangelog.com/ru/1.1.0/), версии — [Semantic Versioning](https://semver.org/lang/ru/). Политика версий описана в [docs/releasing.md](docs/releasing.md).

## [Не выпущено]

## [0.1.0] — 2026-10-27

Первый выпуск.

### Добавлено

- Поиск хостов сканированием подсети (nmap) и импорт inventory Ansible в форматах INI и YAML.
- Сбор сведений о хостах без агентов: релиз и срок поддержки Debian, ядра, файловые системы, пользователи, прикладные службы, открытые порты, параметры `sshd`, TLS-сертификаты, пакеты и доступные обновления.
- Оценка уязвимостей по Debian Security Tracker с учётом CISA KEV, FIRST EPSS и CVSS из NVD; список наблюдения.
- Отчёты: сводка по парку, детализация по хостам, CVE и службам; история; выгрузка в CSV и JSON.
- Работа в изолированном контуре: внутренние зеркала и ручная загрузка трекера Debian.
- Образ для `linux/amd64` и `linux/arm64`, Docker Compose, Helm-чарт.
- CI: тесты, линтеры, проверка чарта, e2e-установка в kind; публикация образа и чарта в GHCR.

[Не выпущено]: https://github.com/didaktikm/amberventory/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/didaktikm/amberventory/releases/tag/v0.1.0
