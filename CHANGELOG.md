# Changes / Изменения

## 3.1.0 — English interface and forwarding performance

- Select Russian or English from menu item `8` or with `sudo proto-cascade language ru|en`. Use `--lang en` before a command to change the language for one invocation.
- Configuration validation and compilation reuse parsed matches. The compiler omits unreachable SSH and IPv6 neighbor discovery guards while retaining protection for rules that can match management traffic.
- Failed saves restore the previous configuration and its backup. Installation checks the rules with the kernel before replacing the installed program, and operations stop if an external chain references a managed chain.

## 3.1.0 — английский интерфейс и производительность переадресации

- Русский и английский доступны в пункте `8` или через `sudo proto-cascade language ru|en`. Параметр `--lang en` перед командой меняет язык одного запуска.
- Проверка и сборка конфигурации повторно используют разобранные условия. Компилятор пропускает проверки SSH и IPv6 Neighbor Discovery для правил, которые заведомо не могут затронуть защищаемый трафик.
- При ошибке сохранения восстанавливаются предыдущая конфигурация и её резервная копия. Установщик проверяет правила в ядре перед заменой программы, а операции останавливаются при внешней ссылке на управляемую цепочку.

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
