#!/bin/bash
# =============================================================================
# Suricata -> Wazuh integration (all-in-one Wazuh server on Debian/Parrot)
#
# What it does:
#   1. Points Suricata at real network interfaces: by default EVERY interface
#      that has a default route, i.e. both the wired and the wireless
#      connection (the stock "eth0" does not exist on this machine, which is
#      why suricata.service is failing).
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
#   sudo bash suricata-wazuh-integration.sh -i YOUR_WIRED_INTERFACE    # wired only
#   sudo bash suricata-wazuh-integration.sh -i YOUR_WIRED_INTERFACE,YOUR_WIRELESS_INTERFACE
#                                                                   # explicit list
#   sudo bash suricata-wazuh-integration.sh --agents              # also configure agents
#
# REPLACE BEFORE SHARING: Review host-specific interface names, addresses, usernames,
# versions, logs, and configuration examples. Never include credentials or generated secrets.
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
    -h|--help)      sed -n 2,27p "$0"; exit 0 ;;
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
