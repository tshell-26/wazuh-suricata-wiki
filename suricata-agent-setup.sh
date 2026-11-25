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
#   sudo bash suricata-agent-setup.sh --home-net YOUR_AGENT_PUBLIC_IP/32
#                                    # replace with the agent's public address if applicable
#
# Safe to re-run: files are backed up and nothing is added twice.
# REPLACE BEFORE SHARING: Review host-specific addresses, usernames, versions, logs,
# and configuration examples. Never include credentials or generated secrets.
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
    -h|--help)      sed -n 2,21p "$0"; exit 0 ;;
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
  ""|MANAGER_IP|MANAGER_IP_ADDRESS) die "Manager address in $OSSEC_CONF is not set (found: '${MANAGER:-none}')." ;;
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
