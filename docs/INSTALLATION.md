# Installation, update and removal

[Русский](INSTALLATION.ru.md) · [User guide](USER-GUIDE.md) · [Troubleshooting](TROUBLESHOOTING.md)

## Before installation

Use a Linux machine with systemd: Ubuntu 24.04 or Debian 12+. Ubuntu 24.04 is the validation platform; a separate complete Debian matrix is not claimed. Bash, Python 3.11+, iptables/ip6tables and iproute2 are required. On supported Debian-based systems, the installer uses apt for missing Python, iptables and iproute2, which needs access to package repositories.

Before changing forwarding, have independent VM console access, identify all gateway SSH ports, and check local addresses and the route to the destination. Docker must use the iptables backend; iptables-nft is supported, native Docker nftables is not. Active UFW/firewalld and conflicting legacy installations require administrator coordination rather than automatic disabling. Follow [migration](MIGRATION.md) first when replacing an old-name installation.

## Install from Git

```bash
git clone https://github.com/mrPortnov/proto-cascade.git
cd proto-cascade
sudo bash install-proto-cascade.sh --install
sudo proto-cascade
```

The installer contains all runtime code and its MIT notice. A first installation creates an empty configuration, enables the service/timer and applies saved configuration. Reinstallation retains existing JSON and its previous backup.

Check each unit **separately**:

```bash
systemctl is-enabled proto-cascade.service
systemctl is-active proto-cascade.service
systemctl is-enabled proto-cascade-reconcile.timer
systemctl is-active proto-cascade-reconcile.timer
sudo proto-cascade --list
sudo proto-cascade --check
```

The primary service is oneshot; `active (exited)` is normal after application. The timer should be `active (waiting)`. `proto-cascade-reconcile.service` may be inactive between successful invocations.

## Single-file installation and another VM

Download and inspect the source before running it:

```bash
curl --fail --location --output install-proto-cascade.sh \
  https://raw.githubusercontent.com/mrPortnov/proto-cascade/main/install-proto-cascade.sh
bash -n install-proto-cascade.sh
sudo bash install-proto-cascade.sh --install
```

`main` can change. Replace it in the URL with a full commit SHA to obtain a repeatable source version. You can transfer this single file to a VM without GitHub access using your own secure transport. Missing apt packages still need an accessible package source or prior installation.

The menu discovers the new VM's own interfaces/addresses. If transferring JSON, review `interface`, `listen`, `target`, `source`, protected ports and return routes. Do not transfer the old `/run` cache or lock.

## Installed objects

| Object | Purpose |
| --- | --- |
| `/usr/local/bin/proto-cascade` | Standalone root-owned command, mode 0755. |
| `/etc/proto-cascade/` | Configuration directory, mode 0700. |
| `/etc/proto-cascade/rules.json` | Current JSON, mode 0600. |
| `/etc/proto-cascade/rules.previous.json` | One previous saved configuration. |
| `/etc/systemd/system/proto-cascade.service` | Apply at startup after network/Docker ordering. |
| `/etc/systemd/system/proto-cascade-reconcile.service` | Check and restore owned hooks. |
| `/etc/systemd/system/proto-cascade-reconcile.timer` | Periodic reconciliation, first countdown relative to timer activation. |
| `/etc/sysctl.d/99-proto-cascade.conf` | Forwarding settings, created when needed. |
| `/run/proto-cascade-state.json` | Temporary state cache. |
| `/run/lock/proto-cascade.lock` | Operation lock. |
| `proto-cascade-FORWARD`, `proto-cascade-DNAT`, `proto-cascade-SNAT` | Owned filter/nat chains in the selected address families. |

## Update

1. Keep a private copy of JSON and, if present, `rules.previous.json`. For example:

   ```bash
   backup_dir="/root/proto-cascade-backup-$(date +%Y%m%d-%H%M%S)"
   sudo install -d -m 700 "$backup_dir"
   sudo cp -a /etc/proto-cascade/rules.json "$backup_dir/"
   ```

2. In your clone, obtain the updated source, check it against the existing configuration and install it:

   ```bash
   git pull --ff-only
   sudo bash install-proto-cascade.sh --check
   sudo bash install-proto-cascade.sh --install
   ```

3. Check the list, preflight, each service and actual client connections, including Docker and administrative SSH.

For a single-file installation, download the chosen updated file and run the same `--check` and `--install`. Menu item 7 reinstalls the running file's content; obtain a newer file first to upgrade. Installation replaces the command/units while preserving JSON and its previous backup. Reinstallation should not duplicate owned hooks.

## Reboot and diagnostics

At boot the service applies saved rules. Check a real client connection and:

```bash
sudo proto-cascade --diagnose
systemctl status proto-cascade.service proto-cascade-reconcile.timer
sudo journalctl -u proto-cascade.service -u proto-cascade-reconcile.service -n 80 --no-pager
```

Logs/diagnostics can contain infrastructure addresses. Replace them with documentation values and remove sensitive information before sharing.

## Removal

Keep a private configuration backup and console access. Perform these administrator actions only on the intended machine.

1. Stop automatic repair, clear owned rules and disable startup:

   ```bash
   sudo systemctl disable --now proto-cascade-reconcile.timer
   sudo systemctl stop proto-cascade-reconcile.service
   sudo proto-cascade clear --yes
   sudo systemctl disable --now proto-cascade.service
   ```

2. Confirm Docker, SSH and other routing still work. Clearing leaves empty owned chains. After checking that they are empty and unreferenced, delete only those specific chains; IPv4 example:

   ```bash
   sudo iptables -t filter -X proto-cascade-FORWARD
   sudo iptables -t nat -X proto-cascade-DNAT
   sudo iptables -t nat -X proto-cascade-SNAT
   ```

   Repeat with `ip6tables` for existing IPv6 chains if used. Do not globally flush tables or Docker chains. `-X` refuses a nonempty/referenced chain; investigate instead of forcing cleanup.

3. Remove the installed product files:

   ```bash
   sudo rm -- /usr/local/bin/proto-cascade \
     /etc/systemd/system/proto-cascade.service \
     /etc/systemd/system/proto-cascade-reconcile.service \
     /etc/systemd/system/proto-cascade-reconcile.timer
   sudo systemctl daemon-reload
   ```

4. Retain the JSON as a backup or remove it separately after checking your saved copy. Remove `/etc/sysctl.d/99-proto-cascade.conf` only after reviewing other forwarding consumers. Removing that file does not reset current kernel values. Do not automatically disable shared forwarding: Docker, VPN or other services may need it.
