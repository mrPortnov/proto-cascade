# Переход со старого имени / Legacy migration

Version 3.0.0 uses `proto-cascade`, `/etc/proto-cascade`, `proto-cascade-*` firewall chains and `proto-cascade*` systemd units. JSON remains schema version 2. The following steps apply specifically to the previous local 2.x manager. Unknown original/intermediate versions need an individual rule audit; there is no universal safe cleanup. Work during maintenance with independent console access, private backups and a preserved administrative SSH connection.

## С предыдущей локальной версии 2.x

1. Сохраните `/etc/kaskad/rules.json` и `rules.previous.json` в приватное место. Снимите локальные `iptables-save` / `ip6tables-save` для аварийного разбора; эти файлы могут содержать адреса вашей инфраструктуры.
2. Остановите таймер: `sudo systemctl stop kaskad-v2-reconcile.timer`. Старой командой `sudo gokaskad clear --yes` снимите её правила/подключения. Проверьте обе таблицы/семейства, Docker и административный доступ.
3. Выполните `sudo systemctl disable --now kaskad-v2.service kaskad-v2-reconcile.timer`, затем `sudo systemctl stop kaskad-v2-reconcile.service`. Проверьте `is-active` и `is-enabled` каждого старого unit по отдельности.
4. Старый `clear` оставляет пустые цепочки. Для `iptables` и, если использовался IPv6, `ip6tables` проверьте `-S KASKAD2-FORWARD`, `-t nat -S KASKAD2-DNAT`, `-t nat -S KASKAD2-SNAT` и отсутствие ссылок в `*-save`. **Только пустые цепочки без ссылок** удаляйте через `-X` с конкретным именем и правильной таблицей. Глобальные очистки firewall или цепочек Docker недопустимы.
5. Установите `sudo bash install-proto-cascade.sh --install`. При сообщении о старых службах/цепочках устраните указанный конфликт, не обходите проверку.
6. В приватной копии прежнего JSON проверьте интерфейсы, локальные и целевые IP, сеть клиентов, SSH-порты и маршруты. Сохраните её root с правами 0600 в `/etc/proto-cascade/rules.json`, затем выполните `sudo proto-cascade --check` и `sudo proto-cascade --apply`.
7. Проверьте новые клиентские подключения, SSH шлюза и назначения, Docker, основную службу и таймер. Сохраните старый установщик/резервные копии приватно до завершения проверки.

Не переносите старый `/run`-кеш, lock или sysctl-файл под новым именем. Старые binary/unit и `/etc/sysctl.d/99-kaskad-v2.conf` можно удалить отдельно после успешного перехода и проверки других потребителей forwarding.

## Original upstream or intermediate installers

Older versions can use `kaskad.service`, `KASKAD-*` chains or direct rules in shared chains. First identify the exact installation and remove only its rules/startup while preserving Docker and administrative access. Untagged direct rules cannot always be detected automatically. Do not apply the 2.x cleanup steps to an unknown version or run both managers concurrently.

For a known 2.x installation: privately back up JSON and firewall snapshots; stop the old timer; clear rules with the old command; disable/stop every old unit; delete only confirmed empty/unreferenced owned chains; install the new manager; review/import schema-2 JSON with mode 0600; check/apply and test real connections. Never globally flush the firewall. A new installation does not automatically read the old JSON.

Для возврата остановите новый таймер, очистите свои правила новой командой, отключите новые службы и восстановите старую установку её собственными средствами. Не пытайтесь устранить конфликт одновременным перезапуском двух менеджеров.
