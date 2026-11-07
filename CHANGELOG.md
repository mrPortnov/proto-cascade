# Changes / Изменения

## 3.0.0 — first public source publication, 2026-11-08

- Product command, console, configuration, systemd units and owned firewall chains use the proto-cascade name.
- Installation refuses detected conflicting legacy services/chains; JSON schema version 2 is retained for explicit migration.
- The first reconciliation is scheduled relative to timer activation, avoiding an immediately overdue boot timer after installation/update.
- User documentation covers installation, portable use, interface/IP selection, CLI/JSON, Docker, SSH, update, recovery and removal, with console previews.

## 3.0.0 — первая публичная публикация исходников, 08.11.2026

- Команда, консоль, конфигурация, службы systemd и собственные цепочки firewall используют имя proto-cascade.
- Установка останавливается при обнаружении конфликтующих старых служб/цепочек; для явной миграции сохранена схема JSON версии 2.
- Первая сверка отсчитывается от включения таймера, устраняя немедленный запуск просроченного boot-таймера после установки/обновления.
- Пользовательские инструкции охватывают установку, перенос, выбор интерфейса/IP, CLI/JSON, Docker, SSH, обновление, восстановление и удаление; добавлены примеры консоли.
