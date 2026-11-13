# wazuh-zabbix-template

![Zabbix](https://img.shields.io/badge/zabbix-7.0-red)
![Wazuh](https://img.shields.io/badge/wazuh-4.14-005571)
![License](https://img.shields.io/badge/license-Apache%202.0-blue)

Zabbix 7.0 templates for the Wazuh central components and the Wazuh agent. The templates follow the layout of the official Zabbix templates (`templates/app/...`): one directory per template, a YAML export and a README with the macros, items, triggers and LLD rules.

## Templates

| Directory | Template | Data source |
|-----------|----------|-------------|
| [templates/wazuh_manager_http](templates/wazuh_manager_http/README.md) | Wazuh manager by HTTP | Wazuh server API (55000/TCP), Script item with JWT login |
| [templates/wazuh_indexer_http](templates/wazuh_indexer_http/README.md) | Wazuh indexer by HTTP | OpenSearch REST API (9200/TCP), HTTP agent items |
| [templates/wazuh_dashboard_http](templates/wazuh_dashboard_http/README.md) | Wazuh dashboard by HTTP | OpenSearch Dashboards `GET /api/status` (443/TCP), HTTP agent item |
| [templates/wazuh_agent](templates/wazuh_agent/README.md) | Wazuh agent by Zabbix agent, Wazuh agent by Zabbix agent active | `wazuh-agentd.state`, `VERSION.json` and the process list, read by Zabbix agent on the host |
| [templates/wazuh_all_in_one](templates/wazuh_all_in_one/README.md) | Wazuh all-in-one | Links the manager, indexer and dashboard templates for a single-node deployment |

What they cover:

- **Manager:** API availability and version, daemon states (LLD), analysisd and remoted statistics, queue usage (LLD), configuration validation, cluster status and node health (LLD), ruleset synchronization, agent connection summary, available updates.
- **Indexer:** cluster health and shard counts, shard limit usage, disk watermarks, per-node heap, disk, CPU, file descriptors, thread pool rejections and circuit breakers (LLD), time of the last alert in `wazuh-alerts-*`.
- **Dashboard:** overall state, plugin states (LLD), heap, event loop delay, response times, connections, uptime.
- **Agent:** daemon processes, connection status, last keep-alive and ACK, event and message rates, anti-flooding buffer, state file age, agent version.

The agent has no REST API, so the agent template reads local files. The connection state of all agents is also collected centrally by the manager template.

## Requirements

- Zabbix server or proxy 7.0 or newer.
- Wazuh 4.14. Tested with Wazuh 4.14.9 (manager, indexer 2.19.6, dashboard 2.19.6, agent) and Zabbix 7.0.22 with a 7.0.28 proxy.
- The HTTP and Script items run on the Zabbix server or proxy that monitors the host, so it must reach the API ports.

## Installation

1. Import the YAML file of the template: *Data collection > Templates > Import*. The all-in-one file contains the three linked templates.
2. Link the template to a host and set the host macros: `{$WAZUH.API.HOST}`, `{$WAZUH.INDEXER.HOST}`, `{$WAZUH.DASHBOARD.HOST}` and the matching `USER` and `PASSWORD` macros. Store passwords as secret macros.
3. For the agent template, grant the zabbix user read access on each agent host (see below).

Each template README lists all macros with their defaults.

## Monitoring users

Use dedicated read-only accounts, not `wazuh-wui` or `admin`.

### Wazuh server API

The manager template needs these RBAC actions (Wazuh API RBAC reference):

| Action | Resource | Endpoints used |
|--------|----------|----------------|
| `manager:read` | `*:*:*` | `/manager/info`, `/manager/status`, `/manager/daemons/stats`, `/manager/configuration/validation` |
| `cluster:status` | `*:*:*` | `/cluster/status` |
| `cluster:read` | `node:id:*` | `/cluster/local/info`, `/cluster/healthcheck`, `/cluster/ruleset/synchronization` |
| `agent:read` | `agent:id:*` | `/agents/summary/status` |

`/manager/version/check` has no RBAC action: any authenticated user can call it.

Create the user, policies and role with an administrator token (`TOKEN`):

```sh
API=https://wazuh-server:55000
H=(-k -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json")

curl "${H[@]}" -X POST "$API/security/users" -d '{"username":"zbx_monitor","password":"<password>"}'
curl "${H[@]}" -X POST "$API/security/policies" -d '{"name":"zbx_monitor_manager","policy":{"actions":["manager:read","cluster:status"],"resources":["*:*:*"],"effect":"allow"}}'
curl "${H[@]}" -X POST "$API/security/policies" -d '{"name":"zbx_monitor_cluster","policy":{"actions":["cluster:read"],"resources":["node:id:*"],"effect":"allow"}}'
curl "${H[@]}" -X POST "$API/security/policies" -d '{"name":"zbx_monitor_agents","policy":{"actions":["agent:read"],"resources":["agent:id:*"],"effect":"allow"}}'
curl "${H[@]}" -X POST "$API/security/roles" -d '{"name":"zbx_monitor"}'

# Use the IDs returned by the calls above.
curl "${H[@]}" -X POST "$API/security/roles/<role_id>/policies?policy_ids=<id1>,<id2>,<id3>"
curl "${H[@]}" -X POST "$API/security/users/<user_id>/roles?role_ids=<role_id>"
```

### Wazuh indexer

The indexer template needs the cluster action group `cluster_monitor` and `indices:data/read/search` on the alerts index pattern. With the OpenSearch security REST API:

```sh
IDX=https://wazuh-indexer:9200

curl -k -u admin -X PUT "$IDX/_plugins/_security/api/roles/zabbix_monitor" -H "Content-Type: application/json" -d '{
  "cluster_permissions": ["cluster_monitor"],
  "index_permissions": [{"index_patterns": ["wazuh-alerts-*"], "allowed_actions": ["indices:data/read/search"]}]
}'
curl -k -u admin -X PUT "$IDX/_plugins/_security/api/internalusers/zbx_monitor" -H "Content-Type: application/json" -d '{"password": "<password>"}'
curl -k -u admin -X PUT "$IDX/_plugins/_security/api/rolesmapping/zabbix_monitor" -H "Content-Type: application/json" -d '{"users": ["zbx_monitor"]}'
```

The same user can be set in the dashboard macros: `GET /api/status` only needs a user that can log in.

### Wazuh agent

Zabbix agent runs as the user `zabbix`, which cannot read `/var/ossec`. Grant read access with POSIX ACLs (package `acl`):

```sh
setfacl -m u:zabbix:x /var/ossec /var/ossec/var /var/ossec/var/run
setfacl -m u:zabbix:r /var/ossec/VERSION.json /var/ossec/var/run/wazuh-agentd.state
setfacl -d -m u:zabbix:r /var/ossec /var/ossec/var/run
```

The default ACLs keep the access when Wazuh recreates the files. On some hosts `wazuh-agentd.state` is created with mode 0640 and gets a new inode on every write. No Zabbix agent restart is needed.

Do not add `zabbix` to the `wazuh` group. That group can write `/var/ossec/etc/ossec.conf`, and the agent runs the commands configured there (`<localfile>` with `command` or `full_command`, the `command` wodle) as root. With `system.run` allowed in Zabbix agent, this is a path to root.

To remove the access:

```sh
setfacl -x u:zabbix /var/ossec /var/ossec/var /var/ossec/var/run /var/ossec/VERSION.json /var/ossec/var/run/wazuh-agentd.state
setfacl -d -x u:zabbix /var/ossec /var/ossec/var/run
```

## TLS

Wazuh generates self-signed certificates by default, so the templates do not verify certificates. For the manager template set `{$HTTP.TLS.VERIFY}` to `full` when the Zabbix server or proxy trusts the API certificate.

The indexer and dashboard HTTP agent items send the monitoring user with Basic authentication and do not set *SSL verify peer* and *SSL verify host*. These fields do not accept macros. To verify the certificates, add the Wazuh root CA (`root-ca.pem`) to the trust store of the Zabbix server or proxy and enable both options on the template items after import.

## Building

The YAML files and the template READMEs are generated from the TypeScript sources in [tools/](tools/):

```sh
bun tools/build.ts
```

Edit the sources, not the generated files. UUIDs are derived from the template name and the item key, so a rebuild keeps them stable and a re-import updates the existing templates.

## Upgrading from the old template

The previous single file `template-wazuh-7.0.yaml` ("Template Wazuh API by Script") is replaced by the manager template. Some item keys are the same in both. To keep the history:

1. Unlink the old template from the host without clearing it (*Unlink*, not *Unlink and clear*).
2. Link the new template. Zabbix attaches the existing items with the same keys to the new template and keeps their history.
3. Delete the items that remain from the old template when they are no longer needed.

## License

Apache License 2.0, see [LICENSE](LICENSE).

## Author

Created by Adam "tick" Pielak, [wazuh.blog](https://wazuh.blog).
