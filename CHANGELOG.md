# Changelog

## 7.0-1 - 2026-11-13

- Replaced `template-wazuh-7.0.yaml` with five templates in `templates/`: Wazuh manager by HTTP, Wazuh indexer by HTTP, Wazuh dashboard by HTTP, Wazuh agent by Zabbix agent (passive and active), Wazuh all-in-one.
- Manager: Script item with JWT login to the Wazuh server API, dependent items, LLD for daemons, analysisd queues and cluster nodes.
- Indexer: HTTP agent items on the OpenSearch REST API, LLD per node, shard limit and watermark items, last alert time.
- Dashboard: HTTP agent item on `GET /api/status`, LLD per plugin.
- Agent: state file, VERSION.json and process checks; read access through POSIX ACLs.
- Template files and READMEs built by `tools/build.ts`.
- README: monitoring users for the server API and the indexer, agent ACL setup, upgrade path from the old template.
- License badge corrected to Apache 2.0.
