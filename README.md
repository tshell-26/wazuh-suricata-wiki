# Wazuh + Suricata Lab

A hands-on lab for connecting Suricata IDS events to Wazuh, configuring a Wazuh server and agents, and troubleshooting event delivery.

## Start here

Read [Wazuh-Suricata-Lab-Setup.md](Wazuh-Suricata-Lab-Setup.md) before running either script:

- [`suricata-wazuh-integration.sh`](suricata-wazuh-integration.sh) configures Suricata and Wazuh on the all-in-one server.
- [`suricata-agent-setup.sh`](suricata-agent-setup.sh) configures Suricata and log collection on an enrolled agent.

Both scripts make system-level changes and require root. Review the scripts and verify the host, interface, network, and version-specific instructions for your own lab before running them.

## Replace lab-specific details

<!-- REPLACE BEFORE PUBLIC RELEASE: Review every marker in the guide and scripts. Substitute your own values only where required, and keep real credentials, private keys, certificates, logs, generated archives, and sensitive network details out of Git. -->

The setup guide uses placeholders for addresses, interface names, users, and host-specific values. Replace them with values appropriate to your lab when following the instructions; do not commit real credentials or generated Wazuh installer archives.

## Contents

- [Full lab setup guide](Wazuh-Suricata-Lab-Setup.md)
- Wazuh server integration script
- Wazuh agent setup script

## License

<!-- REPLACE: Choose and add a license if you want to grant others permission to reuse this project. -->
