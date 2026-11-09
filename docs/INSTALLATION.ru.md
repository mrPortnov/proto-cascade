# Установка, обновление и удаление

[English](INSTALLATION.md) · [Руководство](USER-GUIDE.ru.md) · [Решение проблем](TROUBLESHOOTING.md)

## Перед установкой

Нужна Linux-машина с systemd: Ubuntu 24.04 или Debian 12+. На Ubuntu 24.04 проводились испытания; отдельная полная матрица Debian не заявляется. Скрипт требует Bash, Python 3.11+, iptables/ip6tables и iproute2. Для недостающих Python, iptables и iproute2 установщик использует apt; доступ к репозиториям пакетов должен работать.

До изменения переадресации проверьте:

- Есть независимый доступ к консоли ВМ, особенно если управление идёт через SSH.
- Известны все SSH-порты самого шлюза, адреса интерфейсов и маршрут к другой машине.
- Docker использует iptables backend. iptables-nft поддерживается; native nftables backend Docker — нет.
- Активные UFW/firewalld или конфликтующая старая установка требуют предварительного согласования правил; установщик их не отключает.

Для старого имени продукта сначала выполните [миграцию](MIGRATION.md).

## Установка из репозитория

```bash
git clone https://github.com/mrPortnov/proto-cascade.git
cd proto-cascade
sudo bash install-proto-cascade.sh --install
sudo proto-cascade
```

Исходный файл содержит весь runtime-код и текст MIT. При первой установке создаётся конфигурация без правил. Затем включаются служба и таймер, применяется сохранённая конфигурация. Если правила уже были, переустановка сохраняет их и предыдущую резервную копию.

Проверьте службы **по отдельности**:

```bash
systemctl is-enabled proto-cascade.service
systemctl is-active proto-cascade.service
systemctl is-enabled proto-cascade-reconcile.timer
systemctl is-active proto-cascade-reconcile.timer
sudo proto-cascade --list
sudo proto-cascade --check
```

`proto-cascade.service` — oneshot-служба: нормальное состояние после применения `active (exited)`. Таймер должен быть `active (waiting)`. Служба `proto-cascade-reconcile.service` может быть `inactive` между успешными запусками — это нормально.

## Установка одним файлом и перенос на другую ВМ

На машине с доступом к GitHub скачайте файл, изучите его и затем запустите:

```bash
curl --fail --location --output install-proto-cascade.sh \
  https://raw.githubusercontent.com/mrPortnov/proto-cascade/main/install-proto-cascade.sh
bash -n install-proto-cascade.sh
sudo bash install-proto-cascade.sh --install
```

`main` может обновляться. Для повторяемой установки замените `main` в URL полным SHA выбранного коммита. Для переноса на ВМ без доступа к GitHub передайте этот файл любым своим защищённым способом. Если зависимости отсутствуют, для apt всё равно потребуется доступ к пакетам или заранее подготовленный локальный источник.

На новой ВМ меню определит **её** интерфейсы и адреса. При переносе существующего JSON вручную проверьте `interface`, `listen`, `target`, `source`, защищённые порты и обратные маршруты. Старый `/run`-кеш и lock-файл переносить не нужно.

## Что устанавливается

| Путь или объект | Назначение |
| --- | --- |
| `/usr/local/bin/proto-cascade` | Самостоятельная команда, root, права 0755. |
| `/etc/proto-cascade/` | Каталог конфигурации, права 0700. |
| `/etc/proto-cascade/rules.json` | Текущий JSON, права 0600. |
| `/etc/proto-cascade/rules.previous.json` | Одна предыдущая сохранённая конфигурация. |
| `/etc/proto-cascade/language` | Сохранённый язык `ru` или `en`. Его задаёт пункт 8 меню или команда `language`. |
| `/etc/systemd/system/proto-cascade.service` | Применение при старте после сети/Docker. |
| `/etc/systemd/system/proto-cascade-reconcile.service` | Сверка и восстановление собственных подключений. |
| `/etc/systemd/system/proto-cascade-reconcile.timer` | Периодическая сверка, первый отсчёт после включения таймера. |
| `/etc/sysctl.d/99-proto-cascade.conf` | Настройки forwarding; создаётся, когда нужны соответствующие изменения. |
| `/run/proto-cascade-state.json` | Временный кеш состояния. |
| `/run/lock/proto-cascade.lock` | Блокировка одновременных операций. |
| `proto-cascade-FORWARD`, `proto-cascade-DNAT`, `proto-cascade-SNAT` | Собственные цепочки filter/nat в используемых семействах. |

## Обновление

1. Сохраните конфигурацию и, если есть, `rules.previous.json` в приватное место. Например, создайте каталог с уникальным временем:

   ```bash
   backup_dir="/root/proto-cascade-backup-$(date +%Y%m%d-%H%M%S)"
   sudo install -d -m 700 "$backup_dir"
   sudo cp -a /etc/proto-cascade/rules.json "$backup_dir/"
   ```

2. В копии репозитория получите исходники и проверьте новую реализацию на текущей конфигурации:

   ```bash
   git pull --ff-only
   sudo bash install-proto-cascade.sh --check
   sudo bash install-proto-cascade.sh --install
   ```

3. Проверьте `--list`, `--check`, службы по отдельности и реальные подключения клиента, включая Docker и административный SSH.

Для установки из одного файла скачайте выбранную новую версию и выполните те же `--check` и `--install`. Пункт 7 меню переустанавливает запущенный файл. Установка сохраняет конфигурацию, её предыдущую копию и выбранный язык. При обновлении с 3.0.0 схема остаётся версии 2, а интерфейс открывается на русском до сохранения предпочтения.

## Перезагрузка и диагностика

После перезагрузки служба применяет сохранённые правила. Проверьте фактическое клиентское соединение и:

```bash
sudo proto-cascade --diagnose
systemctl status proto-cascade.service proto-cascade-reconcile.timer
sudo journalctl -u proto-cascade.service -u proto-cascade-reconcile.service -n 80 --no-pager
```

Диагностика и журналы могут содержать адреса вашей инфраструктуры. Перед отправкой кому-либо замените их демонстрационными значениями и удалите секреты.

## Удаление

Выполняйте удаление с сохранённой приватной копией JSON и доступом к консоли. Это действия администратора на выбранной машине.

1. Остановите автоматическое восстановление, затем снимите собственные правила:

   ```bash
   sudo systemctl disable --now proto-cascade-reconcile.timer
   sudo systemctl stop proto-cascade-reconcile.service
   sudo proto-cascade clear --yes
   sudo systemctl disable --now proto-cascade.service
   ```

2. Проверьте, что Docker, SSH и другие маршруты работают. `clear` оставляет пустые собственные цепочки. После проверки их пустоты и отсутствия ссылок удалите **конкретные** цепочки; пример для IPv4:

   ```bash
   sudo iptables -t filter -X proto-cascade-FORWARD
   sudo iptables -t nat -X proto-cascade-DNAT
   sudo iptables -t nat -X proto-cascade-SNAT
   ```

   Если использовался IPv6, выполните аналогичные команды с `ip6tables` для существующих цепочек. Не используйте глобальные очистки таблиц или цепочек Docker. Команда `-X` откажется удалять непустую цепочку или цепочку со ссылками — сначала разберите причину.

3. Удалите только файлы установленного продукта:

   ```bash
   sudo rm -- /usr/local/bin/proto-cascade \
     /etc/systemd/system/proto-cascade.service \
     /etc/systemd/system/proto-cascade-reconcile.service \
     /etc/systemd/system/proto-cascade-reconcile.timer
   sudo systemctl daemon-reload
   ```

4. Конфигурацию оставьте как резервную копию либо удалите её отдельно после проверки сохранённой копии. Файл `/etc/sysctl.d/99-proto-cascade.conf` можно удалить после проверки других потребителей forwarding. Удаление файла не выключает текущие значения ядра. Не отключайте общий forwarding автоматически: он может быть нужен Docker, VPN или другим службам.
