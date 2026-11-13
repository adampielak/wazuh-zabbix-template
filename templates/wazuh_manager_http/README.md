# Wazuh manager by HTTP

## Overview

Monitors a Wazuh server (manager) node through the Wazuh server API: API availability, daemon states, analysisd and remoted statistics, configuration validation and cluster state.
On the master node or on a standalone manager it also collects agent connection summary, cluster node health, ruleset synchronization and available updates.

## Requirements

Zabbix version: 7.0 and higher.

## Setup

1. Create a read-only Wazuh API user, for example "zbx_monitor", with read-only policies: manager:read and cluster:status on *:*:*, cluster:read on node:id:*, agent:read on agent:id:*. The README in the repository root has the API calls.
2. Link the template to a host and set {$WAZUH.API.HOST} to the Wazuh server node. Link it to one host per cluster node: node-local data is collected on each node, cluster-wide data on the master only.
3. Set {$WAZUH.API.USER} and {$WAZUH.API.PASSWORD}. Change {$WAZUH.API.SCHEME} and {$WAZUH.API.PORT} if the API does not listen on https:55000.
4. Wazuh generates self-signed certificates by default, so {$HTTP.TLS.VERIFY} defaults to "none". Set it to "full" if the API certificate is trusted by the Zabbix server or proxy.

Tested with Wazuh 4.14 and Zabbix 7.0.

### Macros used

|Name|Description|Default|
|----|-----------|-------|
|{$WAZUH.API.SCHEME}|Wazuh server API scheme (http or https).|https|
|{$WAZUH.API.HOST}|Hostname or IP address of the Wazuh server node.|<SET WAZUH API HOST>|
|{$WAZUH.API.PORT}|Wazuh server API port.|55000|
|{$WAZUH.API.USER}|Wazuh server API user with read-only RBAC permissions.|zbx_monitor|
|{$WAZUH.API.PASSWORD}|Password of the Wazuh server API user.||
|{$WAZUH.DATA.INTERVAL}|Update interval of the API data item.|1m|
|{$WAZUH.HTTP_PROXY}|HTTP proxy for API requests, for example http://proxy.example.com:3128. Leave empty to connect directly.||
|{$HTTP.TLS.VERIFY}|TLS certificate verification for the script item: "none" - disabled, "peer" - verify the certificate chain and expiration, "full" - full verification. Any other value enables full verification. To override the setting for this template only, define the macro with the context "Wazuh", e.g. {$HTTP.TLS.VERIFY:"Wazuh"}. Requires a Zabbix server or proxy version that supports TLS options in the HttpRequest constructor.|none|
|{$WAZUH.AGENTS.DISCONNECTED.MAX.WARN}|Maximum share of disconnected agents, in %, for the trigger expression.|10|
|{$WAZUH.QUEUE.UTIL.MAX.WARN}|Warning threshold of analysisd and remoted queue utilization, in %.|80|
|{$WAZUH.QUEUE.UTIL.MAX.CRIT}|Critical threshold of analysisd and remoted queue utilization, in %.|95|
|{$WAZUH.CLUSTER.KEEPALIVE.MAX.WARN}|Maximum age of the last keep-alive received by the master from a worker node.|5m|
|{$WAZUH.LLD.FILTER.DAEMON.MATCHES}|Filter of discoverable Wazuh daemons by name.|.*|
|{$WAZUH.LLD.FILTER.DAEMON.NOT_MATCHES}|Filter to exclude discovered Wazuh daemons by name.|CHANGE_IF_NEEDED|
|{$WAZUH.DAEMON.OPTIONAL.MATCHES}|Daemons that run only when enabled in ossec.conf. No "is not running" trigger is created for them. Remove a daemon from the list if your configuration requires it.|^wazuh-(agentlessd\|csyslogd\|dbd\|integratord\|maild\|reportd)$|

### Items

|Name|Description|Type|Key and additional info|
|----|-----------|----|-----------------------|
|Get API data|Logs in to the Wazuh server API and collects manager, daemon, statistics and cluster data in one JSON document. A failed API section is reported in the "API errors" item and does not stop the other sections.|SCRIPT|wazuh.manager.get|
|API availability|Result of the login to the Wazuh server API: 1 - logged in, 0 - connection or authentication failed.|DEPENDENT|wazuh.api.available|
|API errors|Errors returned by the API requests of the last collection. Empty when all requests succeeded.|DEPENDENT|wazuh.api.errors|
|API version|Version of the Wazuh server API.|DEPENDENT|wazuh.api.version|
|Version|Version of the Wazuh manager.|DEPENDENT|wazuh.manager.version|
|Configuration status|Result of the Wazuh configuration validation (GET /manager/configuration/validation).|DEPENDENT|wazuh.manager.config.valid|
|Cluster: Enabled|Whether the cluster is enabled in the manager configuration.|DEPENDENT|wazuh.cluster.enabled|
|Cluster: Running|Whether the cluster daemon is running.|DEPENDENT|wazuh.cluster.running|
|Cluster: Node role|Role of this node: master, worker or standalone.|DEPENDENT|wazuh.cluster.role|
|Cluster: Node name|Name of this node in the cluster. Empty on a standalone manager.|DEPENDENT|wazuh.cluster.node|
|Cluster: Name|Name of the cluster. Empty on a standalone manager.|DEPENDENT|wazuh.cluster.name|
|Analysisd: Uptime|Time since wazuh-analysisd started.|DEPENDENT|wazuh.analysisd.uptime|
|Analysisd: Events received per second|Events received by wazuh-analysisd.|DEPENDENT|wazuh.analysisd.events.received.rate|
|Analysisd: Events processed per second|Events processed by the rule engine.|DEPENDENT|wazuh.analysisd.events.processed.rate|
|Analysisd: Events dropped per second|Events dropped by wazuh-analysisd because an input queue was full. Sum of all counters in events.received_breakdown.dropped_breakdown.|DEPENDENT|wazuh.analysisd.events.dropped.rate|
|Analysisd: Alerts written per second|Alerts written to alerts.log and alerts.json.|DEPENDENT|wazuh.analysisd.alerts.written.rate|
|Analysisd: Archives written per second|Events written to the archives. Zero when logall and logall_json are disabled.|DEPENDENT|wazuh.analysisd.archives.written.rate|
|Analysisd: Firewall events written per second|Events written to the firewall log.|DEPENDENT|wazuh.analysisd.firewall.written.rate|
|Analysisd: Bytes received per second|Bytes received by wazuh-analysisd.|DEPENDENT|wazuh.analysisd.bytes.received.rate|
|Remoted: Uptime|Time since wazuh-remoted started.|DEPENDENT|wazuh.remoted.uptime|
|Remoted: TCP sessions|Open TCP sessions with agents.|DEPENDENT|wazuh.remoted.tcp_sessions|
|Remoted: Bytes received per second|Bytes received from agents.|DEPENDENT|wazuh.remoted.bytes.received.rate|
|Remoted: Bytes sent per second|Bytes sent to agents.|DEPENDENT|wazuh.remoted.bytes.sent.rate|
|Remoted: Event messages per second|Event messages received from agents.|DEPENDENT|wazuh.remoted.messages.event.rate|
|Remoted: Control messages per second|Control messages (keep-alive, startup, shutdown, request) received from agents.|DEPENDENT|wazuh.remoted.messages.control.rate|
|Remoted: Discarded messages per second|Messages from agents discarded by wazuh-remoted.|DEPENDENT|wazuh.remoted.messages.discarded.rate|
|Remoted: Receive queue size|Capacity of the remoted receive queue, in messages.|DEPENDENT|wazuh.remoted.queue.size|
|Remoted: Receive queue usage|Messages waiting in the remoted receive queue.|DEPENDENT|wazuh.remoted.queue.usage|
|Remoted: Receive queue utilization|Utilization of the remoted receive queue.|DEPENDENT|wazuh.remoted.queue.util|
|Wazuh DB: Queries per second|Queries received by wazuh-db.|DEPENDENT|wazuh.db.queries.rate|

### Triggers

|Name|Description|Priority|
|----|-----------|--------|
|Wazuh: API is not available|Login to the Wazuh server API failed for 3 minutes. Check the "API errors" item, wazuh-apid on the node, the network path and the API credentials.|AVERAGE|
|Wazuh: Failed to fetch API data|The script item returned no data for 30 minutes. Check the item error and the Zabbix server or proxy log.|WARNING|
|Wazuh: API requests returned errors|One or more API requests failed. The items fed by that request have no new data. A common cause is a missing RBAC permission of the monitoring user.|INFO|
|Wazuh: Version has changed|The Wazuh manager version has changed. Acknowledge to close the problem manually.|INFO|
|Wazuh: Configuration is not valid|GET /manager/configuration/validation reports an error. The manager will fail to start with the current ossec.conf. Run /var/ossec/bin/wazuh-analysisd -t on the node.|AVERAGE|
|Wazuh: Cluster is enabled but not running|The cluster is enabled in ossec.conf but wazuh-clusterd is not running. The node does not synchronize with the cluster.|HIGH|
|Wazuh: Analysisd has been restarted|wazuh-analysisd started less than 10 minutes ago.|INFO|
|Wazuh: Remoted has been restarted|wazuh-remoted started less than 10 minutes ago.|INFO|
|Wazuh: Analysisd is dropping events|wazuh-analysisd dropped events for 5 minutes because input queues were full. Events that are dropped do not generate alerts. Check the analysisd queue utilization and the event rate.|WARNING|
|Wazuh: Remoted receive queue utilization is high|Messages from agents wait in the remoted receive queue. When the queue is full, remoted discards messages.|WARNING|
|Wazuh: Remoted receive queue utilization is critical|The remoted receive queue is almost full. Remoted discards messages from agents when the queue is full.|HIGH|

### LLD rule Cluster-wide metrics discovery

Creates the agent summary and update items on the master node or on a standalone manager. Nothing is discovered on a worker node.

#### Item prototypes for Cluster-wide metrics discovery

|Name|Description|Type|Key and additional info|
|----|-----------|----|-----------------------|
|Agents: Active|Agents connected to the manager.|DEPENDENT|wazuh.agents.active[{#SINGLETON}]|
|Agents: Disconnected|Agents that were connected and lost the connection.|DEPENDENT|wazuh.agents.disconnected[{#SINGLETON}]|
|Agents: Never connected|Registered agents that never connected.|DEPENDENT|wazuh.agents.never_connected[{#SINGLETON}]|
|Agents: Pending|Agents waiting for the connection to complete.|DEPENDENT|wazuh.agents.pending[{#SINGLETON}]|
|Agents: Total|Registered agents.|DEPENDENT|wazuh.agents.total[{#SINGLETON}]|
|Agents: Disconnected, in %|Share of disconnected agents in all registered agents.|DEPENDENT|wazuh.agents.disconnected.pct[{#SINGLETON}]|
|Agents: Configuration not synchronized|Agents whose group configuration is not synchronized.|DEPENDENT|wazuh.agents.not_synced[{#SINGLETON}]|
|Cluster: Nodes|Nodes reported by the cluster health check. Zero on a standalone manager.|DEPENDENT|wazuh.cluster.nodes[{#SINGLETON}]|
|Latest available version|Newest Wazuh release newer than the installed version, as reported by GET /manager/version/check (major, then minor, then patch). Empty when the installation is up to date or the update check is disabled.|DEPENDENT|wazuh.update.latest[{#SINGLETON}]|

#### Trigger prototypes for Cluster-wide metrics discovery

|Name|Description|Priority|
|----|-----------|--------|
|Wazuh: Too many disconnected agents|The share of disconnected agents is above the threshold.|WARNING|
|Wazuh: New version is available|The Wazuh update check reports a newer release. Read the release notes before upgrading.|INFO|

### LLD rule Cluster nodes discovery

Discovers cluster nodes from GET /cluster/healthcheck on the master node.

#### Item prototypes for Cluster nodes discovery

|Name|Description|Type|Key and additional info|
|----|-----------|----|-----------------------|
|Node [{#NODE.NAME}]: Active agents|Agents connected to the node.|DEPENDENT|wazuh.cluster.node.agents[{#NODE.NAME}]|
|Node [{#NODE.NAME}]: Version|Wazuh version of the node.|DEPENDENT|wazuh.cluster.node.version[{#NODE.NAME}]|
|Node [{#NODE.NAME}]: Time since last keep-alive|Time since the master received the last keep-alive from the worker node. Calculated with the clock of the Zabbix server or proxy.|DEPENDENT|wazuh.cluster.node.keepalive.age[{#NODE.NAME}]|
|Node [{#NODE.NAME}]: Ruleset synchronized|Whether the node ruleset matches the master (GET /cluster/ruleset/synchronization).|DEPENDENT|wazuh.cluster.node.ruleset.synced[{#NODE.NAME}]|

#### Trigger prototypes for Cluster nodes discovery

|Name|Description|Priority|
|----|-----------|--------|
|Wazuh: Cluster node [{#NODE.NAME}]: Version differs from the master|All cluster nodes must run the same Wazuh version.|WARNING|
|Wazuh: Cluster node [{#NODE.NAME}]: No keep-alive from the worker|The master has not received a keep-alive from the worker node. Check wazuh-clusterd on the worker and the network on port 1516/TCP.|AVERAGE|
|Wazuh: Cluster node [{#NODE.NAME}]: Node is not reported by the master|The worker node is missing from GET /cluster/healthcheck for 10 minutes. The node is disconnected from the cluster or was removed.|AVERAGE|
|Wazuh: Cluster node [{#NODE.NAME}]: Ruleset is not synchronized|The node ruleset differs from the master for 15 minutes. The node may evaluate events with outdated rules or decoders.|WARNING|

### LLD rule Analysisd queues discovery

Discovers the input and output queues of wazuh-analysisd.

#### Item prototypes for Analysisd queues discovery

|Name|Description|Type|Key and additional info|
|----|-----------|----|-----------------------|
|Analysisd: Queue [{#QUEUE}] utilization|Utilization of the analysisd queue. A full input queue makes analysisd drop events.|DEPENDENT|wazuh.analysisd.queue.util[{#QUEUE}]|
|Analysisd: Queue [{#QUEUE}] size|Capacity of the analysisd queue, in events.|DEPENDENT|wazuh.analysisd.queue.size[{#QUEUE}]|

#### Trigger prototypes for Analysisd queues discovery

|Name|Description|Priority|
|----|-----------|--------|
|Wazuh: Analysisd queue [{#QUEUE}] utilization is high|Events wait in the analysisd queue. A full input queue makes analysisd drop events.|WARNING|
|Wazuh: Analysisd queue [{#QUEUE}] utilization is critical|The analysisd queue is almost full.|HIGH|

### LLD rule Daemons discovery

Discovers Wazuh daemons from GET /manager/status. wazuh-clusterd is skipped when the cluster is disabled.

#### Item prototypes for Daemons discovery

|Name|Description|Type|Key and additional info|
|----|-----------|----|-----------------------|
|Daemon [{#DAEMON}]: State|State of the daemon reported by GET /manager/status.|DEPENDENT|wazuh.daemon.state[{#DAEMON}]|

#### Trigger prototypes for Daemons discovery

|Name|Description|Priority|
|----|-----------|--------|
|Wazuh: Daemon [{#DAEMON}] is not running|The daemon is not running. Daemons that are optional by configuration are matched by {$WAZUH.DAEMON.OPTIONAL.MATCHES} and have no trigger.|AVERAGE|

## Author

Created by Adam "tick" Pielak, [wazuh.blog](https://wazuh.blog).
