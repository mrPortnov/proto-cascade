# Решение проблем / Troubleshooting

Диагностика: `sudo proto-cascade --diagnose`. Журналы: `sudo journalctl -u proto-cascade.service -u proto-cascade-reconcile.service -n 80 --no-pager`. Перед публикацией вывода уберите реальные адреса и чувствительные данные.

## Русский

| Ситуация | Что проверить |
| --- | --- |
| Меню требует терминал | Запускайте из интерактивного SSH/консоли. Для автоматизации используйте CLI `--check`, `--apply`, `add`, `remove`. |
| Нет подходящих интерфейсов | Проверьте `ip -j address show`: интерфейс поднят, адрес пригоден и завершил DAD. Loopback/link-local/Docker/veth отфильтрованы. Нажмите `r` после изменения сети. |
| Внешнего публичного адреса нет в списке | При NAT выбирайте адрес, действительно назначенный ВМ. На внешнем роутере отдельно настройте путь к ней. |
| Адрес не назначен интерфейсу | После изменения адресов отредактируйте `listen`/`interface` или пересоздайте правило через меню. |
| Нет маршрута до цели | Проверьте `ip -4 route get TARGET` или `ip -6 route get TARGET`, шлюз и IPv6-маршруты. Цель должна быть другой машиной вне Docker bridge. |
| TCP-порт зарезервирован для управления | Выберите другой входящий порт, например 2222 для назначения 22. Не убирайте действующий SSH-порт шлюза из защиты ради переадресации на нём. |
| Другая операция уже выполняется | Подождите окончания текущей операции/сверки и повторите. Не удаляйте lock-файл работающего процесса. |
| Активен UFW/firewalld или другой backend | Согласуйте конфигурацию firewall вручную. iptables-nft допустим; native Docker nftables не поддерживается. Не отключайте firewall или Docker наугад. |
| На управляемую цепочку есть внешняя ссылка | Посмотрите ссылки `-j` и `-g` в `sudo iptables-save` или `sudo ip6tables-save`. Измените источник внешнего правила перед повторной попыткой. |
| Обнаружена предыдущая установка | Выполните [миграцию](MIGRATION.md). Пустые старые цепочки тоже могут быть причиной отказа. |
| Правило проверено, но соединения нет | Проверка маршрута и правил не проверяет удалённую службу. Проверьте входящий firewall/маршрут до ВМ, `source` и порт, удалённую службу/firewall, опубликованные порты Docker и обратный маршрут при `snat: none`. |
| Соединение попадает в контейнер | Docker published ports имеют приоритет. Выберите другой входящий адрес/порт для переадресации на другую машину. |
| После перезапуска Docker временно не работает правило | Дождитесь таймера или вызовите `sudo proto-cascade --reconcile`, затем проверьте фактическое соединение. |
| `active (exited)` у основной службы | Это нормальное состояние oneshot-службы после успешного применения. Проверяйте её отдельно от таймера. |
| Откат не проходит | Резервный JSON должен соответствовать текущим интерфейсам, адресам и маршрутам. Проверьте его приватную копию, не обходите валидацию. |

Изменения правил действуют на новые соединения. Существующие conntrack-сессии могут продолжать прежнее сопоставление; программа намеренно не очищает глобальные соединения. Для проверки откройте новое соединение клиента.

## English

Use `sudo proto-cascade --diagnose` and the journal command above. Redact real infrastructure details before sharing.

| Situation | Check |
| --- | --- |
| Menu requires a terminal | Use interactive SSH/console, or CLI commands for automation. |
| No selectable interfaces | Check `ip -j address show`, enabled flags, usable addresses and completed DAD. Loopback/link-local/Docker/veth are filtered; use `r` after network changes. |
| Public IP absent behind NAT | Select an address actually assigned to the VM; configure the external router separately. |
| Address not assigned to interface | Update `listen`/`interface` after address changes or recreate the rule through the menu. |
| No route to target | Use `ip -4 route get TARGET` or `ip -6 route get TARGET`; check gateways/IPv6 routes. The target must be another machine outside a Docker bridge. |
| Management TCP port reserved | Choose another incoming port, such as 2222 to destination 22. Retain protection for the gateway's actual SSH port. |
| Another operation is running | Wait for the running operation/reconciliation and retry. Do not delete a live process's lock file. |
| Active UFW/firewalld or backend conflict | Coordinate firewall configuration manually. iptables-nft works; native Docker nftables is unsupported. |
| External reference to a managed chain | Inspect `-j` and `-g` references in `sudo iptables-save` or `sudo ip6tables-save`. Update the source of the external rule before retrying. |
| Legacy installation detected | Follow [migration](MIGRATION.md); even empty old chains can trigger the guard. |
| Preflight passes but connection fails | Check the path/firewall to the VM, source CIDR/port, remote service/firewall, Docker published ports and return routing for `snat: none`. Preflight does not contact the target service. |
| Connection goes to a container | Docker published ports have priority; select another incoming address/port. |
| Temporary failure after Docker restart | Wait for the timer or run `sudo proto-cascade --reconcile`, then retest the connection. |
| Primary service is `active (exited)` | Normal for the successfully applied oneshot unit. Check it separately from the timer. |
| Rollback rejected | Backup JSON must match current interfaces, addresses and routes. Validate a private copy rather than bypassing checks. |

Rule changes apply to new connections. Existing conntrack sessions can retain their previous mapping; the manager does not globally flush connections. Open a new client connection for validation.

## Сообщение о проблеме / Reporting

В [Issues](https://github.com/mrPortnov/proto-cascade/issues) укажите версию из заголовка меню, ОС, backend, команды и ожидаемый результат. Используйте минимальную конфигурацию с демонстрационными адресами. Для уязвимостей и чувствительных материалов используйте [SECURITY.md](../SECURITY.md).

Include the menu version, OS, backend, reproduction commands and expected result in Issues. Use documentation addresses and a minimal configuration. Follow SECURITY.md for sensitive findings.
