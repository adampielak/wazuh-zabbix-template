# Wazuh dashboard by HTTP

## Overview

Monitors the Wazuh dashboard (OpenSearch Dashboards) through its status API: overall state, state of each plugin, Node.js heap, event loop delay, response times and uptime.

## Requirements

Zabbix version: 7.0 and higher.

## Setup

1. Link the template to a host and set {$WAZUH.DASHBOARD.HOST} to the Wazuh dashboard node.
2. Set {$WAZUH.DASHBOARD.USER} and {$WAZUH.DASHBOARD.PASSWORD} to a Wazuh indexer user. With the security plugin enabled, GET /api/status requires authentication; any user that can log in to the dashboard is sufficient.
3. Change {$WAZUH.DASHBOARD.PORT} if the dashboard does not listen on 443.

Certificates are not verified: the HTTP agent item does not set "verify_peer" and "verify_host".

Tested with Wazuh dashboard 4.14 (OpenSearch Dashboards 2.19) and Zabbix 7.0.

### Macros used

|Name|Description|Default|
|----|-----------|-------|
|{$WAZUH.DASHBOARD.SCHEME}|Wazuh dashboard scheme (http or https).|https|
|{$WAZUH.DASHBOARD.HOST}|Hostname or IP address of the Wazuh dashboard.|<SET WAZUH DASHBOARD HOST>|
|{$WAZUH.DASHBOARD.PORT}|Wazuh dashboard port.|443|
|{$WAZUH.DASHBOARD.USER}|User for the status API.||
|{$WAZUH.DASHBOARD.PASSWORD}|Password of the status API user.||
|{$WAZUH.DASHBOARD.RESPONSE_TIME.MAX.WARN}|Maximum response time of the dashboard port for the trigger expression.|10s|
|{$WAZUH.DASHBOARD.HEAP.MAX.WARN}|Warning threshold of Node.js heap usage, in % of the heap size limit.|90|
|{$WAZUH.DASHBOARD.LLD.FILTER.PLUGIN.MATCHES}|Filter of discoverable plugins by status ID.|.*|
|{$WAZUH.DASHBOARD.LLD.FILTER.PLUGIN.NOT_MATCHES}|Filter to exclude discovered plugins by status ID.|CHANGE_IF_NEEDED|

### Items

|Name|Description|Type|Key and additional info|
|----|-----------|----|-----------------------|
|Service status|Checks if the dashboard port is accepting TCP connections.|SIMPLE|net.tcp.service["{$WAZUH.DASHBOARD.SCHEME}","{$WAZUH.DASHBOARD.HOST}","{$WAZUH.DASHBOARD.PORT}"]|
|Service response time|Checks the performance of the TCP service.|SIMPLE|net.tcp.service.perf["{$WAZUH.DASHBOARD.SCHEME}","{$WAZUH.DASHBOARD.HOST}","{$WAZUH.DASHBOARD.PORT}"]|
|Get status|Returns the state and metrics of the dashboard. The API answers 503 when the overall state is red.|HTTP_AGENT|wazuh.dashboard.get_status|
|Overall state|Overall state of the dashboard: the worst state of all plugins.|DEPENDENT|wazuh.dashboard.state|
|Version|OpenSearch Dashboards version.|DEPENDENT|wazuh.dashboard.version|
|Uptime|Time since the Node.js process started.|DEPENDENT|wazuh.dashboard.uptime|
|Heap used|Node.js heap in use.|DEPENDENT|wazuh.dashboard.heap.used|
|Heap size limit|Maximum Node.js heap size.|DEPENDENT|wazuh.dashboard.heap.limit|
|Heap usage|Node.js heap in use, in % of the heap size limit.|DEPENDENT|wazuh.dashboard.heap.util|
|Event loop delay|Node.js event loop delay. A high delay makes the dashboard slow for every user.|DEPENDENT|wazuh.dashboard.event_loop_delay|
|Response time, avg|Average response time of HTTP requests in the last collection interval of the dashboard.|DEPENDENT|wazuh.dashboard.response_time.avg|
|Response time, max|Maximum response time of HTTP requests in the last collection interval of the dashboard.|DEPENDENT|wazuh.dashboard.response_time.max|
|Concurrent connections|Open HTTP connections.|DEPENDENT|wazuh.dashboard.connections|

### Triggers

|Name|Description|Priority|
|----|-----------|--------|
|Wazuh dashboard: Service is down|The dashboard port is not accepting TCP connections.|AVERAGE|
|Wazuh dashboard: Service response time is too high|The TCP service of the dashboard responds slowly.|WARNING|
|Wazuh dashboard: Failed to fetch status|The status API returned no data for 30 minutes. Check the "Get status" item error and the API credentials.|WARNING|
|Wazuh dashboard: State is RED|At least one core service or plugin is red. The dashboard is not usable. A red "core:opensearch" means the dashboard cannot reach the Wazuh indexer.|HIGH|
|Wazuh dashboard: State is YELLOW|At least one core service or plugin is degraded.|AVERAGE|
|Wazuh dashboard: Version has changed|The dashboard version has changed. Acknowledge to close the problem manually.|INFO|
|Wazuh dashboard: Has been restarted|The dashboard process started less than 10 minutes ago.|INFO|
|Wazuh dashboard: Heap usage is high|The Node.js process is close to the heap size limit and can stop with an out of memory error.|WARNING|

### LLD rule Plugins discovery

Discovers the core services and plugins listed by the status API.

#### Item prototypes for Plugins discovery

|Name|Description|Type|Key and additional info|
|----|-----------|----|-----------------------|
|Plugin [{#PLUGIN}]: State|State of the plugin or core service.|DEPENDENT|wazuh.dashboard.plugin.state[{#PLUGIN}]|

#### Trigger prototypes for Plugins discovery

|Name|Description|Priority|
|----|-----------|--------|
|Wazuh dashboard: Plugin [{#PLUGIN}] is not green|The plugin or core service reports a degraded or failed state.|WARNING|

## Author

Created by Adam "tick" Pielak, [wazuh.blog](https://wazuh.blog).
