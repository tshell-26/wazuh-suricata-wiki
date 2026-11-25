# Wazuh + Suricata Lab Setup

How this lab's Wazuh SIEM server was built, how Suricata network IDS alerts were connected to the Wazuh dashboard, and how to roll the same setup out to agent machines. It covers every command and script used, the mistakes made along the way, and how each one was fixed.

> **Versions:** Wazuh 4.14.10 (manager, indexer, dashboard), Filebeat 7.10.2, Suricata 7.0.10, Emerging Threats Open ruleset.
> **Server OS:** Parrot OS 7 (Debian-based).

## Contents

1. [Architecture](#1-architecture)
2. [Lessons learned](#2-lessons-learned)
3. [Install the Wazuh server](#3-install-the-wazuh-server)
4. [Connect Suricata on the server](#4-connect-suricata-on-the-server)
5. [View Suricata alerts in the dashboard](#5-view-suricata-alerts-in-the-dashboard)
6. [Add agent machines](#6-add-agent-machines)
7. [Troubleshooting](#7-troubleshooting)
8. [Hardening and maintenance](#8-hardening-and-maintenance)
9. [Reference](#9-reference)

---

## 1. Architecture

One machine runs every Wazuh component (an **all-in-one** install). Other machines run only the Wazuh agent and, optionally, Suricata.

```text
 Agent machine(s)                         Wazuh server (all-in-one)
 ┌──────────────────────┐                 ┌───────────────────────────────────────────┐
 │ Suricata             │                 │ Suricata ──> eve.json                     │
 │   └─> eve.json       │                 │                 │                         │
 │ wazuh-agent          │  1514/1515 TCP  │ wazuh-manager <─┘  (monitors itself: 000)  │
 │   └─ reads eve.json ─┼────────────────>│   └─> alerts.json ──> Filebeat            │
 └──────────────────────┘                 │                        └─> wazuh-indexer  │
                                          │                              └─> dashboard │
                                          └─────────────────────── https://<SERVER_HOST_OR_IP> ┘
```

| Item | Lab value |
|---|---|
| Server wired interface | `<SERVER_WIRED_INTERFACE>`, `<SERVER_WIRED_IP>` |
| Server wireless interface | `<SERVER_WIRELESS_INTERFACE>`, `<SERVER_WIRELESS_IP>` |
| Dashboard | `https://<SERVER_HOST_OR_IP>` (port 443) |
| Server's own agent ID | `000` (it monitors itself) |

Replace `<SERVER_HOST_OR_IP>` with the server address or hostname reachable by the agent. Values in angle brackets are examples to replace locally, not literal shell input.

---

## 2. Lessons learned

| Mistake | What happened | Fix |
|---|---|---|
| Installed `wazuh-agent` on the server | apt **removed `wazuh-manager`** without asking (because of `-y`). The two packages conflict on Linux. | Never install the agent on the server. The manager already monitors its own host as agent `000`. |
| Used `WAZUH_MANAGER="<SERVER_HOST_OR_IP>"` literally | The agent was configured to connect to the placeholder host and failed to start. | Substitute the server's reachable address or hostname locally; don't commit a real one. |
| Reinstalled only the manager | The Wazuh API users were reset to their default passwords, so the dashboard showed **"No API available to connect"**. | Point the dashboard at the reset password, then change the API passwords (sections 7.4 and 8). |
| Suricata pointed at `eth0` | The machine has no `eth0`, so `suricata.service` kept failing. | Set the real interface names in `af-packet:` (the integration script does this). |
| Tested with `testmynids.org` | The domain has expired and is now parked, so no alert fires. | Use the Nmap user-agent test in section 5. |

---

## 3. Install the Wazuh server

### 3.1 Add the Wazuh apt repository

Imports the Wazuh signing key and adds the 4.x repository. These are needed for both server and agent installs.

```bash
curl -s https://packages.wazuh.com/key/GPG-KEY-WAZUH | sudo gpg --no-default-keyring --keyring gnupg-ring:/usr/share/keyrings/wazuh.gpg --import && sudo chmod 644 /usr/share/keyrings/wazuh.gpg
```
```bash
echo "deb [signed-by=/usr/share/keyrings/wazuh.gpg] https://packages.wazuh.com/4.x/apt/ stable main" | sudo tee /etc/apt/sources.list.d/wazuh.list
```
```bash
sudo apt-get update
```

### 3.2 Run the all-in-one installer

Installs the indexer, manager, Filebeat and dashboard on one machine. `-a` means all-in-one; `-i` skips the OS check, which Parrot would otherwise fail.

```bash
curl -sO https://packages.wazuh.com/4.14/wazuh-install.sh
```
```bash
cd ~ && sudo bash wazuh-install.sh -a -i
```

It takes about 3 to 20 minutes. At the end it prints the dashboard user and a generated password. Save the password in a password manager immediately; do not paste it into this guide, a terminal transcript, or a public issue.

### 3.3 Recover the generated passwords

The installer stores generated passwords and cluster certificates in `~/wazuh-install-files.tar`. Keep that file outside the repository in secure storage. Never commit the archive, its extracted contents, passwords, or certificates.

Access the archive only from a trusted local session and store its contents securely. Do not add the archive, extracted password file, or credentials to this repository.

If the generated passwords are lost, don't try to recover them: set new ones with `wazuh-passwords-tool.sh`, following the official [Wazuh password management](https://documentation.wazuh.com/current/user-manual/user-administration/password-management.html) guide. On an all-in-one server, see [Changing the passwords for all users](https://documentation.wazuh.com/current/user-manual/user-administration/password-management.html#changing-the-passwords-for-all-users). The tool prints the new passwords, so run it in a private terminal and save them straight to a password manager.

### 3.4 Check the install

All five services should report `active`, and the dashboard should answer on 443.

```bash
systemctl is-active wazuh-manager wazuh-indexer wazuh-dashboard filebeat
```
```bash
ss -ltn | grep -E ':(443|1514|1515|9200|55000)\b'
```

---

## 4. Connect Suricata on the server

`suricata-wazuh-integration.sh` takes an installed Suricata and connects it to Wazuh. It:

1. Points Suricata at the real interfaces, by default every interface with a default route (wired **and** wireless). Each interface gets its own `cluster-id`.
2. Downloads the Emerging Threats Open rules with `suricata-update`.
3. Validates the config, then enables and starts Suricata.
4. Adds `/var/log/suricata/eve.json` to the manager's log collection as JSON. Wazuh's built-in rules (`0475-suricata_rules.xml`) decode the alerts, so nothing else is needed.
5. Optionally (`--agents`) pushes the same log setting to the `default` agent group.
6. Fires a harmless test alert and checks it reached Wazuh.

It is safe to re-run. It backs up every file it changes, and it always rebuilds `suricata.yaml` from the pristine copy it saves on the first run (`suricata.yaml.orig-before-wazuh`).

```bash
sudo apt-get install -y suricata suricata-update
```
```bash
sudo bash suricata-wazuh-integration.sh -i "<SERVER_WIRED_INTERFACE>,<SERVER_WIRELESS_INTERFACE>"
```

Other ways to run it:

```bash
sudo bash suricata-wazuh-integration.sh                     # auto: every default-route interface
sudo bash suricata-wazuh-integration.sh -i "<SERVER_WIRED_INTERFACE>"  # wired only
sudo bash suricata-wazuh-integration.sh --agents            # also configure the default agent group
```

> On Wi-Fi in normal (managed) mode, Suricata sees only this machine's own traffic. On a wired port it sees other devices' traffic only if the switch sends it there, for example via a mirror/SPAN port.

<details>
<summary><code>suricata-wazuh-integration.sh</code></summary>

```bash
#!/bin/bash
# =============================================================================
# Suricata -> Wazuh integration (all-in-one Wazuh server on Debian/Parrot)
#
# What it does:
#   1. Points Suricata at real network interfaces: by default EVERY interface
#      that has a default route, i.e. both the wired and the wireless
#      connection (the stock "eth0" often does not exist on modern systems,
#      which makes suricata.service fail).
#   2. Downloads the Emerging Threats Open ruleset with suricata-update.
#   3. Validates the config, then enables and starts Suricata.
#   4. Tells the Wazuh manager to read /var/log/suricata/eve.json (JSON).
#      Wazuh's built-in ruleset (0475-suricata_rules.xml) decodes the alerts.
#   5. Optionally (--agents) pushes the same setting to every agent in the
#      "default" group via centralized config, for agents that run Suricata.
#   6. Fires a harmless test signature and checks the alert reached Wazuh.
#
# Usage:
#   sudo bash suricata-wazuh-integration.sh                       # wired + wireless (auto)
#   sudo bash suricata-wazuh-integration.sh -i <WIRED_INTERFACE>  # wired only
#   sudo bash suricata-wazuh-integration.sh -i <WIRED_INTERFACE>,<WIRELESS_INTERFACE>
#                                                                 # explicit list
#   sudo bash suricata-wazuh-integration.sh --agents              # also configure agents
#
# Safe to re-run: every file is backed up before it is changed, and the Wazuh
# blocks are only added if they are not already there.
# =============================================================================
set -euo pipefail

SURICATA_YAML=/etc/suricata/suricata.yaml
EVE_LOG=/var/log/suricata/eve.json
OSSEC_CONF=/var/ossec/etc/ossec.conf
AGENT_CONF=/var/ossec/etc/shared/default/agent.conf
STAMP=$(date +%F-%H%M%S)
IFACE=""
DO_AGENTS=no

while [ $# -gt 0 ]; do
  case "$1" in
    -i|--interface) IFACE="$2"; shift 2 ;;
    --agents)       DO_AGENTS=yes; shift ;;
    -h|--help)      sed -n '3,/^# ====/{/^# ====/d;p;}' "$0"; exit 0 ;;
    *) echo "Unknown option: $1" >&2; exit 1 ;;
  esac
done

[ "$(id -u)" -eq 0 ] || { echo "Run as root: sudo bash $0" >&2; exit 1; }
command -v suricata >/dev/null || { echo "Suricata is not installed: apt-get install -y suricata suricata-update" >&2; exit 1; }
[ -f "$OSSEC_CONF" ] || { echo "Wazuh manager not found ($OSSEC_CONF)" >&2; exit 1; }

log() { echo -e "\n=== $* ==="; }

# --- 1. Interfaces ------------------------------------------------------------
if [ -z "$IFACE" ]; then
  # Every interface with a default route = wired + wireless, in route-metric order.
  IFACE=$(ip -4 route show default | awk '{m=0; for(i=1;i<=NF;i++){if($i=="metric")m=$(i+1); if($i=="dev")d=$(i+1)} print m, d}' | sort -n | awk '!seen[$2]++{print $2}' | paste -sd,)
fi
IFS=',' read -r -a IFACES <<< "$IFACE"
[ "${#IFACES[@]}" -gt 0 ] || { echo "No interface found; pass one with -i" >&2; exit 1; }
for ifc in "${IFACES[@]}"; do
  ip link show "$ifc" >/dev/null 2>&1 || { echo "Interface '$ifc' does not exist. Pick from: $(ls /sys/class/net | tr '\n' ' ')" >&2; exit 1; }
done
log "1. Configuring Suricata to listen on: ${IFACES[*]}"

# Keep a pristine copy from the first run and always build from it, so re-running
# the script never stacks duplicate interface entries.
ORIG="$SURICATA_YAML.orig-before-wazuh"
[ -f "$ORIG" ] || cp -a "$SURICATA_YAML" "$ORIG"
cp -a "$SURICATA_YAML" "$SURICATA_YAML.bak-$STAMP"

# Rewrite the af-packet: section with one entry per interface. Each capture
# interface needs its own cluster-id (99, 98, ...). "--af-packet" in the systemd
# unit makes Suricata capture on every interface listed here.
awk -v list="$IFACE" '
  /^af-packet:/ {
    print "af-packet:"
    n = split(list, ifs, ",")
    for (i = 1; i <= n; i++) {
      print "  - interface: " ifs[i]
      print "    cluster-id: " (100 - i)
      print "    cluster-type: cluster_flow"
      print "    defrag: yes"
      print ""
    }
    print "  - interface: default"
    print ""
    skip = 1; next
  }
  skip && /^[^[:space:]#]/ { skip = 0 }   # next top-level key ends the section
  skip { next }
  { print }
' "$ORIG" > "$SURICATA_YAML"

# Community ID lets you correlate the same flow across Suricata and other tools.
sed -i -E 's/^([[:space:]]*)community-id: false/\1community-id: true/' "$SURICATA_YAML"
sed -n '/^af-packet:/,/^af-xdp:/p' "$SURICATA_YAML"
echo "Backup: $SURICATA_YAML.bak-$STAMP   (pristine original: $ORIG)"

# --- 2. Rules -----------------------------------------------------------------
log "2. Downloading Emerging Threats Open rules (suricata-update)"
suricata-update
ls -lh /var/lib/suricata/rules/suricata.rules

# --- 3. Validate and start ----------------------------------------------------
log "3. Testing Suricata configuration"
suricata -T -c "$SURICATA_YAML" -v
systemctl enable suricata
systemctl restart suricata
sleep 5
systemctl is-active suricata
tail -n 3 /var/log/suricata/suricata.log

# --- 4. Wazuh manager reads eve.json ------------------------------------------
log "4. Adding $EVE_LOG to the Wazuh manager's log collection"
if grep -q "<location>$EVE_LOG</location>" "$OSSEC_CONF"; then
  echo "Already configured in $OSSEC_CONF"
else
  cp -a "$OSSEC_CONF" "$OSSEC_CONF.bak-$STAMP"
  cat >> "$OSSEC_CONF" <<EOF

<!-- Suricata IDS alerts (added $STAMP) -->
<ossec_config>
  <localfile>
    <log_format>json</log_format>
    <location>$EVE_LOG</location>
  </localfile>
</ossec_config>
EOF
  echo "Added. Backup: $OSSEC_CONF.bak-$STAMP"
fi

# --- 5. Optional: agents in the default group ---------------------------------
if [ "$DO_AGENTS" = yes ]; then
  log "5. Pushing the same setting to agents in the 'default' group"
  if grep -q "<location>$EVE_LOG</location>" "$AGENT_CONF"; then
    echo "Already configured in $AGENT_CONF"
  else
    cp -a "$AGENT_CONF" "$AGENT_CONF.bak-$STAMP"
    awk -v loc="$EVE_LOG" '
      /<\/agent_config>/ && !done {
        print "  <localfile>"
        print "    <log_format>json</log_format>"
        print "    <location>" loc "</location>"
        print "  </localfile>"
        done=1
      }
      { print }
    ' "$AGENT_CONF.bak-$STAMP" > "$AGENT_CONF"
    chown wazuh:wazuh "$AGENT_CONF"; chmod 660 "$AGENT_CONF"
    /var/ossec/bin/verify-agent-conf -f "$AGENT_CONF"
    echo "Added. Agents pick it up within a few minutes. Backup: $AGENT_CONF.bak-$STAMP"
    echo "Each agent still needs Suricata installed and configured locally."
  fi
else
  log "5. Skipping agents (re-run with --agents to configure them)"
fi

# --- Restart Wazuh ------------------------------------------------------------
log "Restarting wazuh-manager"
systemctl restart wazuh-manager
sleep 15
systemctl is-active wazuh-manager
grep -m1 "$EVE_LOG" /var/ossec/logs/ossec.log || echo "(logcollector line not found yet; check /var/ossec/logs/ossec.log)"

# --- 6. End-to-end test -------------------------------------------------------
log "6. Triggering a harmless test signature (Nmap user-agent, ET sid 2024364/2009358)"
# A plain web request to example.com that only *claims* to be Nmap; nothing is scanned.
# (testmynids.org, the usual test site, has expired and no longer triggers alerts.)
sleep 20   # give Suricata time to finish loading ~50k rules
curl -s -o /dev/null -A 'Mozilla/5.0 (compatible; Nmap Scripting Engine; https://nmap.org/book/nse.html)' http://example.com/ || true
sleep 20
echo "Suricata alert in eve.json:"
grep '"event_type":"alert"' "$EVE_LOG" | tail -n 1 | grep -o '"signature":"[^"]*"' || echo "  none yet"
echo "Wazuh alert in alerts.json:"
grep '"groups":\[[^]]*"suricata"' /var/ossec/logs/alerts/alerts.json | tail -n 1 | grep -o '"description":"[^"]*"' || echo "  none yet (can take up to a minute)"

cat <<EOF

Done. In the Wazuh dashboard:
  Threat intelligence -> Threat Hunting -> Events, then filter:  rule.groups: suricata
  (or Explore -> Discover, index wazuh-alerts-*, same filter)
EOF
```

</details>

The resulting capture section in `/etc/suricata/suricata.yaml`:

```yaml
af-packet:
  - interface: <SERVER_WIRED_INTERFACE>
    cluster-id: 99
    cluster-type: cluster_flow
    defrag: yes

  - interface: <SERVER_WIRELESS_INTERFACE>
    cluster-id: 98
    cluster-type: cluster_flow
    defrag: yes

  - interface: default
```

The block appended to `/var/ossec/etc/ossec.conf`:

```xml
<ossec_config>
  <localfile>
    <log_format>json</log_format>
    <location>/var/log/suricata/eve.json</location>
  </localfile>
</ossec_config>
```

---

## 5. View Suricata alerts in the dashboard

Wazuh has no separate Suricata page. Alerts appear with all other events, in the `suricata` rule group (rule `86601`, level 3). Everyday DNS, TLS and flow records stay in `eve.json` and are not shown.

### 5.1 Discover (most reliable)

1. **☰ → Explore → Discover**
2. Index pattern: **`wazuh-alerts-*`**
3. Time range: **Last 7 days**. Clear any filter chips.
4. Search:

```text
rule.groups: suricata
```

Useful columns: `rule.description`, `data.alert.signature`, `data.src_ip`, `data.dest_ip`, `agent.name`.

### 5.2 Threat Hunting

**Threat intelligence → Threat Hunting → Events**, same search and time range. Make sure no single agent is pinned at the top of the page.

### 5.3 Generate a test alert

One ordinary request to `example.com` that only *claims* to be Nmap. Nothing is scanned. It triggers ET rule 2024364, `ET SCAN Possible Nmap User-Agent Observed`.

```bash
curl -s -o /dev/null -A 'Mozilla/5.0 (compatible; Nmap Scripting Engine; https://nmap.org/book/nse.html)' http://example.com/
```

### 5.4 Confirm alerts are stored in the indexer

In **☰ → Indexer management → Dev Tools**, run the following. A `count` of 1 or more means the alerts are stored, and any dashboard problem is only a filter or time range.

```text
GET wazuh-alerts-*/_count?q=rule.groups:suricata
```

---

## 6. Add agent machines

### 6.1 Install the Wazuh agent

Run on **each agent machine, never on the server**. Add the repository first (section 3.1), then install the agent, pinned to the server's version:

```bash
sudo apt-get update && sudo WAZUH_MANAGER="<SERVER_HOST_OR_IP>" apt-get install -y wazuh-agent=4.14.10-1
```
```bash
sudo systemctl daemon-reload && sudo systemctl enable --now wazuh-agent
```

The agent must not be newer than the manager. Optionally, stop upgrades from moving it ahead:

```bash
sudo apt-mark hold wazuh-agent
```

### 6.2 Add Suricata to the agent

`suricata-agent-setup.sh` does the agent-side equivalent of section 4. It:

1. **Refuses to run on the Wazuh server**, and checks that the agent is installed, running, enrolled, and pointed at a real manager address.
2. Warns if less than about 2 GB of RAM is free (the full ruleset needs it).
3. Installs Suricata and `suricata-update` if they are missing.
4. Captures on every default-route interface, downloads rules, validates and starts Suricata.
5. Adds `eve.json` to the **agent's** `ossec.conf` and restarts the agent. No server change is needed.
6. Fires the test alert.

Supported: Debian-based systems (Debian, Ubuntu, Parrot, Kali). Agents with a **public IP** must pass `--home-net <their-ip>/32`, otherwise many rules (including the test rule) won't match.

Copy the script to the agent, then run it there:

```bash
scp suricata-agent-setup.sh <AGENT_USER>@<AGENT_HOST_OR_IP>:~/
```
```bash
sudo bash ~/suricata-agent-setup.sh
```

<details>
<summary><code>suricata-agent-setup.sh</code></summary>

```bash
#!/bin/bash
# =============================================================================
# Suricata setup for a Wazuh AGENT (Debian, Ubuntu, Parrot, Kali)
#
# Run this ON EACH AGENT MACHINE, not on the Wazuh server. It:
#   1. Checks this machine is a connected Wazuh agent (and refuses on a manager).
#   2. Installs Suricata if needed.
#   3. Captures on every interface with a default route (wired + wireless).
#   4. Downloads the Emerging Threats Open rules, validates, starts Suricata.
#   5. Adds /var/log/suricata/eve.json to the agent's log collection.
#   6. Restarts the agent and fires one harmless test alert.
#
# Usage:
#   sudo bash suricata-agent-setup.sh                        # all default-route interfaces
#   sudo bash suricata-agent-setup.sh -i eth0                # one interface
#   sudo bash suricata-agent-setup.sh -i eth0,wlan0          # explicit list
#   sudo bash suricata-agent-setup.sh --home-net <AGENT_PUBLIC_IP>/32
#                                    # replace with the agent's public address if applicable
#
# Safe to re-run: files are backed up and nothing is added twice.
# =============================================================================
set -euo pipefail

SURICATA_YAML=/etc/suricata/suricata.yaml
EVE_LOG=/var/log/suricata/eve.json
OSSEC_CONF=/var/ossec/etc/ossec.conf
CLIENT_KEYS=/var/ossec/etc/client.keys
STAMP=$(date +%F-%H%M%S)
IFACE=""
HOME_NET=""

while [ $# -gt 0 ]; do
  case "$1" in
    -i|--interface) IFACE="${2:?missing interface}"; shift 2 ;;
    --home-net)     HOME_NET="${2:?missing CIDR}"; shift 2 ;;
    -h|--help)      sed -n '3,/^# ====/{/^# ====/d;p;}' "$0"; exit 0 ;;
    *) echo "Unknown option: $1" >&2; exit 1 ;;
  esac
done

log()  { echo -e "\n=== $* ==="; }
die()  { echo "ERROR: $*" >&2; exit 1; }
installed() { dpkg-query -W -f='${Status}' "$1" 2>/dev/null | grep -q 'install ok installed'; }

# --- 1. Safety checks ---------------------------------------------------------
command -v apt-get >/dev/null || die "This script supports Debian-based systems only."
installed wazuh-manager && die "This is the Wazuh SERVER. It is already set up; run this on an agent machine."
installed wazuh-agent   || die "wazuh-agent is not installed. Install and enroll it first."
[ "$(id -u)" -eq 0 ]    || die "Run as root: sudo bash $0"

log "1. Checking the Wazuh agent"
systemctl is-active --quiet wazuh-agent || die "wazuh-agent is not running. Start it: systemctl start wazuh-agent"
[ -s "$CLIENT_KEYS" ] || die "This agent is not enrolled with a manager ($CLIENT_KEYS is empty)."
MANAGER=$(grep -m1 -oP '(?<=<address>)[^<]+' "$OSSEC_CONF" || true)
case "$MANAGER" in
  ""|MANAGER_IP|MANAGER_IP_ADDRESS|*SERVER_HOST_OR_IP*|"<"*">")
    die "Manager address in $OSSEC_CONF is not set (found: '${MANAGER:-none}'). Replace the placeholder with the server's real address." ;;
esac
echo "Agent is running and enrolled. Manager: $MANAGER"

MEM_MB=$(awk '/MemAvailable/ {print int($2/1024)}' /proc/meminfo)
[ "$MEM_MB" -ge 2000 ] || echo "WARNING: only ${MEM_MB} MB RAM free. The full ruleset normally needs about 2 GB."

# --- 2. Install ---------------------------------------------------------------
log "2. Installing Suricata"
if ! command -v suricata >/dev/null; then
  apt-get update -qq || echo "WARNING: apt-get update reported errors; trying the install anyway."
  DEBIAN_FRONTEND=noninteractive apt-get install -y suricata
fi
if ! command -v suricata-update >/dev/null; then
  DEBIAN_FRONTEND=noninteractive apt-get install -y suricata-update
fi
suricata -V
systemctl cat suricata 2>/dev/null | grep -q -- '--af-packet' || \
  echo "WARNING: the suricata service does not start with --af-packet; check /etc/default/suricata."

# --- 3. Interfaces and config -------------------------------------------------
if [ -z "$IFACE" ]; then
  IFACE=$(ip -4 route show default | awk '{m=0; for(i=1;i<=NF;i++){if($i=="metric")m=$(i+1); if($i=="dev")d=$(i+1)} print m, d}' | sort -n | awk '!seen[$2]++{print $2}' | paste -sd,)
fi
[ -n "$IFACE" ] || die "No default-route interface found; pass one with -i."
IFS=',' read -r -a IFACES <<< "$IFACE"
for ifc in "${IFACES[@]}"; do
  ip link show "$ifc" >/dev/null 2>&1 || die "Interface '$ifc' does not exist. Available: $(ls /sys/class/net | tr '\n' ' ')"
done
log "3. Configuring Suricata on: ${IFACES[*]}"

# Always build from the pristine first-run copy so re-runs never stack entries.
ORIG="$SURICATA_YAML.orig-before-wazuh"
[ -f "$ORIG" ] || cp -a "$SURICATA_YAML" "$ORIG"
cp -a "$SURICATA_YAML" "$SURICATA_YAML.bak-$STAMP"
grep -q '^af-packet:' "$ORIG" || die "No af-packet section found in $ORIG."

awk -v list="$IFACE" '
  /^af-packet:/ {
    print "af-packet:"
    n = split(list, ifs, ",")
    for (i = 1; i <= n; i++) {
      print "  - interface: " ifs[i]
      print "    cluster-id: " (100 - i)
      print "    cluster-type: cluster_flow"
      print "    defrag: yes"
      print ""
    }
    print "  - interface: default"
    print ""
    skip = 1; next
  }
  skip && /^[^[:space:]#]/ { skip = 0 }
  skip { next }
  /^default-rule-path:/ { print "default-rule-path: /var/lib/suricata/rules"; next }
  /^rule-files:/ { print "rule-files:"; print "  - suricata.rules"; inrules = 1; next }
  inrules && /^[[:space:]]*(#|-)/ { next }
  inrules { inrules = 0 }
  { print }
' "$ORIG" > "$SURICATA_YAML"

sed -i -E 's/^([[:space:]]*)community-id: false/\1community-id: true/' "$SURICATA_YAML"
if [ -n "$HOME_NET" ]; then
  sed -i -E "0,/^[[:space:]]*HOME_NET:/s|^([[:space:]]*)HOME_NET:.*|\1HOME_NET: \"[$HOME_NET]\"|" "$SURICATA_YAML"
fi
grep -m1 -E '^[[:space:]]*HOME_NET:' "$SURICATA_YAML"
echo "Backup: $SURICATA_YAML.bak-$STAMP"

# --- 4. Rules, validate, start ------------------------------------------------
log "4. Downloading rules and starting Suricata"
suricata-update
suricata -T -c "$SURICATA_YAML"
systemctl enable suricata
systemctl restart suricata
echo "Waiting for the rules to load..."
sleep 45
systemctl is-active --quiet suricata || { tail -n 15 /var/log/suricata/suricata.log; die "Suricata did not stay running."; }
echo "Suricata is running."

# --- 5. Send eve.json to Wazuh ------------------------------------------------
log "5. Adding $EVE_LOG to the agent's log collection"
if grep -q "<location>$EVE_LOG</location>" "$OSSEC_CONF"; then
  echo "Already configured."
else
  cp -a "$OSSEC_CONF" "$OSSEC_CONF.bak-$STAMP"
  cat >> "$OSSEC_CONF" <<EOF

<!-- Suricata IDS alerts (added $STAMP) -->
<ossec_config>
  <localfile>
    <log_format>json</log_format>
    <location>$EVE_LOG</location>
  </localfile>
</ossec_config>
EOF
  echo "Added. Backup: $OSSEC_CONF.bak-$STAMP"
fi
systemctl restart wazuh-agent
sleep 15
systemctl is-active --quiet wazuh-agent || { tail -n 15 /var/ossec/logs/ossec.log; die "wazuh-agent did not restart."; }
grep "Analyzing file: '$EVE_LOG'" /var/ossec/logs/ossec.log | tail -n 1 || echo "(log collection line not found yet)"

# --- 6. Test ------------------------------------------------------------------
log "6. Sending a harmless test alert"
# One ordinary request to example.com that only claims to be Nmap. Nothing is scanned.
curl -s -m 15 -o /dev/null -A 'Mozilla/5.0 (compatible; Nmap Scripting Engine; https://nmap.org/book/nse.html)' http://example.com/ || true
sleep 15
if grep '"event_type":"alert"' "$EVE_LOG" | tail -n 1 | grep -o '"signature":"[^"]*"'; then
  echo "Suricata raised an alert on this agent."
else
  echo "No alert yet. If this machine has a public IP, re-run with --home-net <its-ip>/32."
fi

cat <<EOF

Done. In the Wazuh dashboard: Explore -> Discover -> wazuh-alerts-*, then search:
  rule.groups: suricata AND agent.name: "$(hostname)"
EOF
```

</details>

### 6.3 View one agent's alerts

```text
rule.groups: suricata AND agent.name: "<AGENT_NAME>"
```

---

## 7. Troubleshooting

### 7.1 "Failed to enable unit: Unit wazuh-agent.service does not exist"

The agent package isn't installed. Install it as in section 6.1. If this happens **on the Wazuh server**, stop: the server doesn't need an agent.

### 7.2 Agent service fails to start

Check the configured manager address and the agent's log:

```bash
sudo grep -A3 '<server>' /var/ossec/etc/ossec.conf
```
```bash
sudo tail -n 20 /var/ossec/logs/ossec.log
```

### 7.3 Agent can't reach the server

The agent needs TCP **1514** (events) and **1515** (enrollment) on the server. If `ufw` is active on the server:

```bash
sudo ufw status
```
```bash
sudo ufw allow 1514/tcp && sudo ufw allow 1515/tcp
```

### 7.4 Dashboard: "No API available to connect"

The dashboard cannot authenticate to the Wazuh API on port 55000. This usually happens after the manager is reinstalled and the API users' passwords are reset. Fix it with the official Wazuh procedures:

- **Reset the API passwords and update the dashboard:** [Changing the passwords for all users](https://documentation.wazuh.com/current/user-manual/user-administration/password-management.html#changing-the-passwords-for-all-users). On an all-in-one server, running the tool with the API options (`-A -au wazuh -ap <current-password>`) also updates the `wazuh-wui` password the dashboard uses. Restart `wazuh-dashboard` afterwards.
- **Check the dashboard's API connection settings** in `/usr/share/wazuh-dashboard/data/wazuh/config/wazuh.yml`: [Could not connect to API with ID error](https://documentation.wazuh.com/current/user-manual/wazuh-dashboard/troubleshooting.html#could-not-connect-to-api-with-id-error).
- **Make sure the API is running:** [Wazuh server API seems to be down error](https://documentation.wazuh.com/current/user-manual/wazuh-dashboard/troubleshooting.html#wazuh-server-api-seems-to-be-down-error).

Do not restore or publish a default password, put credentials directly in a script, or commit a dashboard configuration file containing credentials.

### 7.5 Suricata alerts not showing in the dashboard

Follow one alert through each stage. This script restarts the manager and Filebeat, tests Filebeat's connection to the indexer, sends a test alert, compares alert counts before and after, and shows Filebeat errors. It prints no passwords.

<details>
<summary><code>restart-and-trace.sh</code></summary>

```bash
#!/bin/bash
# Restart the Wazuh manager and Filebeat, send one test alert, and show how far it gets.
# Prints no passwords.
ALERTS=/var/ossec/logs/alerts/alerts.json

echo "=== 1. Restarting wazuh-manager and filebeat ==="
sudo systemctl restart wazuh-manager
sudo systemctl restart filebeat
sleep 25
for s in suricata wazuh-manager filebeat wazuh-indexer wazuh-dashboard; do
  echo "$s: $(systemctl is-active "$s")"
done

echo; echo "=== 2. Filebeat connection to the indexer ==="
sudo filebeat test output

echo; echo "=== 3. Sending a test alert ==="
BEFORE=$(sudo grep -c '"groups":\[[^]]*"suricata"' "$ALERTS")
curl -s -o /dev/null -A 'Mozilla/5.0 (compatible; Nmap Scripting Engine; https://nmap.org/book/nse.html)' http://example.com/
sleep 45
AFTER=$(sudo grep -c '"groups":\[[^]]*"suricata"' "$ALERTS")
echo "Suricata alerts in eve.json: $(grep -c '"event_type":"alert"' /var/log/suricata/eve.json)"
echo "Suricata alerts in Wazuh alerts.json: before=$BEFORE after=$AFTER"
sudo grep '"groups":\[[^]]*"suricata"' "$ALERTS" | tail -n 1 | grep -o '"timestamp":"[^"]*"' | head -1

echo; echo "=== 4. Filebeat errors and warnings ==="
sudo sh -c 'grep -hiE "ERROR|WARN" /var/log/filebeat/filebeat* 2>/dev/null | tail -n 8 | cut -c1-300'

echo; echo "=== 5. Filebeat alert module ==="
sudo grep -nE 'module: wazuh|alerts:|archives:|enabled:' /etc/filebeat/filebeat.yml

echo; echo "=== 6. Clock ==="
date
echo TRACE_DONE
```

</details>

How to read the result:

| Stage | Healthy result | If not |
|---|---|---|
| Services | all `active` | `journalctl -u <service>` |
| `filebeat test output` | `talk to server... OK` | Filebeat credentials or certificates |
| `alerts.json` count | goes up after the test | `eve.json` not collected (check `ossec.conf`) |
| Dev Tools `_count` | 1 or more | Filebeat isn't delivering to the indexer |
| Discover | events listed | Time range, filter chips, or index pattern |

`401 Unauthorized` errors timestamped during the install are normal: Filebeat starts before the installer sets its password.

---

## 8. Hardening and maintenance

- **Change reset or default API passwords** using the current official Wazuh procedure (section 7.4). Keep credentials out of scripts, screenshots, logs, and this repository.
- **Pin versions** so a routine upgrade can't split the stack:

```bash
sudo apt-mark hold wazuh-manager wazuh-indexer wazuh-dashboard filebeat
```

- **Reserve the server's IP** in the router (DHCP reservation). Agents lose contact if it changes.
- **Update Suricata rules** regularly:

```bash
sudo suricata-update && sudo systemctl reload suricata
```

- **Keep `~/wazuh-install-files.tar`** in secure storage outside the repository. It contains certificates and generated passwords; do not upload it or its extracted contents.

---

## 9. Reference

### Services

| Service | Role |
|---|---|
| `wazuh-manager` | Analyses events, raises alerts, API on 55000 |
| `wazuh-indexer` | Stores alerts (OpenSearch), port 9200, localhost only |
| `wazuh-dashboard` | Web interface, port 443 |
| `filebeat` | Ships `alerts.json` to the indexer |
| `suricata` | Network IDS, writes `eve.json` |
| `wazuh-agent` | Agent machines only |

### Ports

| Port | Used by |
|---|---|
| 443/tcp | Dashboard |
| 1514/tcp | Agent events |
| 1515/tcp | Agent enrollment |
| 9200/tcp | Indexer (local) |
| 55000/tcp | Wazuh API |

### Files

| Path | Contents |
|---|---|
| `/var/ossec/etc/ossec.conf` | Manager or agent configuration |
| `/var/ossec/logs/ossec.log` | Wazuh's own log |
| `/var/ossec/logs/alerts/alerts.json` | Alerts raised by the manager |
| `/etc/suricata/suricata.yaml` | Suricata configuration |
| `/etc/suricata/suricata.yaml.orig-before-wazuh` | Pristine copy saved by the scripts |
| `/var/lib/suricata/rules/suricata.rules` | Downloaded ruleset |
| `/var/log/suricata/eve.json` | Suricata events and alerts |
| `/var/log/suricata/suricata.log` | Suricata's own log |
| `/usr/share/wazuh-dashboard/data/wazuh/config/wazuh.yml` | Dashboard's API connection |
| `~/wazuh-install-files.tar` | Certificates and generated passwords |
