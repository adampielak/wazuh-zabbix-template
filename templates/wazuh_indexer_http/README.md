# Wazuh indexer by HTTP

## Overview

Monitors the Wazuh indexer (OpenSearch) cluster through its REST API: cluster health, shard allocation and limits, disk watermarks, per-node JVM heap, disk, CPU, file descriptors, thread pool rejections, circuit breakers, and the ingest of Wazuh alerts.

## Requirements

Zabbix version: 7.0 and higher.

## Setup

1. Create an indexer user for monitoring. It needs the cluster permission cluster_monitor and the index permission indices:data/read/search on the alerts index pattern (wazuh-alerts-* by default). The README in the repository root has an example role.
2. Link the template to a host and set {$WAZUH.INDEXER.HOST} to one indexer node, or to a load balancer in front of the cluster. All cluster data is collected through this node, so link the template to one host per cluster.
3. Set {$WAZUH.INDEXER.USER} and {$WAZUH.INDEXER.PASSWORD}.

The Wazuh indexer uses https on port 9200 by default. Certificates are not verified: the HTTP agent items do not set "verify_peer" and "verify_host".

Tested with Wazuh indexer 4.14 (OpenSearch 2.19) and Zabbix 7.0.

### Macros used

|Name|Description|Default|
|----|-----------|-------|
|{$WAZUH.INDEXER.SCHEME}|Wazuh indexer REST API scheme (http or https).|https|
|{$WAZUH.INDEXER.HOST}|Hostname or IP address of a Wazuh indexer node.|<SET WAZUH INDEXER HOST>|
|{$WAZUH.INDEXER.PORT}|Wazuh indexer REST API port.|9200|
|{$WAZUH.INDEXER.USER}|Wazuh indexer user with the cluster_monitor permission.||
|{$WAZUH.INDEXER.PASSWORD}|Password of the Wazuh indexer user.||
|{$WAZUH.INDEXER.RESPONSE_TIME.MAX.WARN}|Maximum response time of the indexer port for the trigger expression.|10s|
|{$WAZUH.INDEXER.HEAP.MAX.WARN}|Warning threshold of JVM heap usage, in %.|85|
|{$WAZUH.INDEXER.HEAP.MAX.CRIT}|Critical threshold of JVM heap usage, in %.|95|
|{$WAZUH.INDEXER.FD.MAX.WARN}|Warning threshold of open file descriptors, in % of the limit.|90|
|{$WAZUH.INDEXER.SHARDS.MAX.WARN}|Warning threshold of shards in use, in % of cluster.max_shards_per_node multiplied by the data nodes.|90|
|{$WAZUH.INDEXER.ALERTS.INDEX}|Index pattern of the Wazuh alerts.|wazuh-alerts-*|
|{$WAZUH.INDEXER.ALERTS.WINDOW}|Time window for counting indexed alerts, in OpenSearch date math units (m, h, d).|10m|

### Items

|Name|Description|Type|Key and additional info|
|----|-----------|----|-----------------------|
|Service status|Checks if the indexer port is accepting TCP connections.|SIMPLE|net.tcp.service["{$WAZUH.INDEXER.SCHEME}","{$WAZUH.INDEXER.HOST}","{$WAZUH.INDEXER.PORT}"]|
|Service response time|Checks the performance of the TCP service.|SIMPLE|net.tcp.service.perf["{$WAZUH.INDEXER.SCHEME}","{$WAZUH.INDEXER.HOST}","{$WAZUH.INDEXER.PORT}"]|
|Get cluster health|Returns the health of the cluster.|HTTP_AGENT|wazuh.indexer.cluster.get_health|
|Get cluster settings|Returns the shard limit and the disk watermarks (transient, persistent and default values).|HTTP_AGENT|wazuh.indexer.cluster.get_settings|
|Get nodes stats|Returns statistics of all cluster nodes.|HTTP_AGENT|wazuh.indexer.nodes.get_stats|
|Get nodes info|Returns the name and version of all cluster nodes.|HTTP_AGENT|wazuh.indexer.nodes.get_info|
|Get alerts ingest|Counts the alerts indexed in the last {$WAZUH.INDEXER.ALERTS.WINDOW} and returns the newest alert timestamp.|HTTP_AGENT|wazuh.indexer.alerts.get|
|Cluster health status|Health of the cluster: green - all shards are assigned, yellow - all primary shards are assigned but one or more replicas are not, red - one or more primary shards are not assigned.|DEPENDENT|wazuh.indexer.cluster.status|
|Cluster name|Name of the cluster.|DEPENDENT|wazuh.indexer.cluster.name|
|Number of nodes|Nodes in the cluster.|DEPENDENT|wazuh.indexer.nodes.number|
|Number of data nodes|Data nodes in the cluster.|DEPENDENT|wazuh.indexer.nodes.data|
|Active primary shards|Active primary shards.|DEPENDENT|wazuh.indexer.shards.primary|
|Active shards|Active primary and replica shards.|DEPENDENT|wazuh.indexer.shards.active|
|Relocating shards|Shards that are moving to another node.|DEPENDENT|wazuh.indexer.shards.relocating|
|Initializing shards|Shards that are being initialized.|DEPENDENT|wazuh.indexer.shards.initializing|
|Unassigned shards|Shards that are not allocated to a node.|DEPENDENT|wazuh.indexer.shards.unassigned|
|Delayed unassigned shards|Shards whose allocation is delayed by the timeout settings.|DEPENDENT|wazuh.indexer.shards.delayed_unassigned|
|Active shards, in %|Ratio of active shards to all shards.|DEPENDENT|wazuh.indexer.shards.active.pct|
|Pending tasks|Cluster-level changes that are not yet executed.|DEPENDENT|wazuh.indexer.cluster.pending_tasks|
|Max shards per node|Effective value of cluster.max_shards_per_node.|DEPENDENT|wazuh.indexer.max_shards_per_node|
|Disk watermark low|Effective value of cluster.routing.allocation.disk.watermark.low, in % of used disk space. -1 when the watermark is an absolute value. Above the low watermark OpenSearch stops allocating new shards to the node.|DEPENDENT|wazuh.indexer.watermark.low|
|Disk watermark high|Effective value of cluster.routing.allocation.disk.watermark.high, in % of used disk space. -1 when the watermark is an absolute value. Above the high watermark OpenSearch moves shards away from the node.|DEPENDENT|wazuh.indexer.watermark.high|
|Disk watermark flood stage|Effective value of cluster.routing.allocation.disk.watermark.flood_stage, in % of used disk space. -1 when the watermark is an absolute value. Above the flood-stage watermark OpenSearch sets a read-only block on every index with a shard on the node. Wazuh alerts are then no longer indexed.|DEPENDENT|wazuh.indexer.watermark.flood|
|Shards in use, in % of the limit|Active and unassigned shards in % of the cluster shard limit (cluster.max_shards_per_node multiplied by the data nodes). New indices cannot be created when the limit is reached, so Wazuh stops indexing alerts at the next daily index rollover.|CALCULATED|wazuh.indexer.shards.limit.util|
|Version|OpenSearch version of the first node in the nodes info response.|DEPENDENT|wazuh.indexer.version|
|Alerts indexed|Alerts indexed in the last {$WAZUH.INDEXER.ALERTS.WINDOW}.|DEPENDENT|wazuh.indexer.alerts.count|
|Newest alert time|Timestamp of the newest alert in the alerts index. No value when no alert was indexed in the time window.|DEPENDENT|wazuh.indexer.alerts.last|

### Triggers

|Name|Description|Priority|
|----|-----------|--------|
|Wazuh indexer: Service is down|The indexer port is not accepting TCP connections.|AVERAGE|
|Wazuh indexer: Service response time is too high|The TCP service of the indexer responds slowly.|WARNING|
|Wazuh indexer: Health is RED|One or more primary shards are unassigned. Some data is unavailable and new alerts for the affected indices are not indexed.|HIGH|
|Wazuh indexer: Health is YELLOW|All primary shards are assigned, but one or more replica shards are not. If a node fails, some data can be unavailable until the node is repaired.|AVERAGE|
|Wazuh indexer: Health is UNKNOWN|The health of the cluster is unknown or cannot be read.|HIGH|
|Wazuh indexer: Number of nodes has decreased|One or more nodes left the cluster.|WARNING|
|Wazuh indexer: Shard usage is close to the cluster limit|When the shard limit is reached, OpenSearch refuses to create new indices and the next daily wazuh-alerts index is not created. Delete old indices, lower the replica count or raise cluster.max_shards_per_node.|WARNING|
|Wazuh indexer: No alerts indexed|No document was written to {$WAZUH.INDEXER.ALERTS.INDEX} in the time window. Check the Filebeat output on the Wazuh server nodes, the indexer health and the disk watermarks.|HIGH|

### LLD rule Nodes discovery

Discovers the nodes of the indexer cluster.

#### Item prototypes for Nodes discovery

|Name|Description|Type|Key and additional info|
|----|-----------|----|-----------------------|
|Node [{#NODE.NAME}]: Get data|Normalized statistics of the node.|DEPENDENT|wazuh.indexer.node.get[{#NODE.NAME}]|
|Node [{#NODE.NAME}]: JVM heap usage|Used JVM heap, in % of the maximum heap.|DEPENDENT|wazuh.indexer.node.heap.util[{#NODE.NAME}]|
|Node [{#NODE.NAME}]: Uptime|Time since the JVM of the node started.|DEPENDENT|wazuh.indexer.node.uptime[{#NODE.NAME}]|
|Node [{#NODE.NAME}]: CPU usage|CPU usage of the node host, as reported by OpenSearch.|DEPENDENT|wazuh.indexer.node.cpu.util[{#NODE.NAME}]|
|Node [{#NODE.NAME}]: Disk total|Total size of the data paths.|DEPENDENT|wazuh.indexer.node.disk.total[{#NODE.NAME}]|
|Node [{#NODE.NAME}]: Disk available|Disk space available to OpenSearch on the data paths.|DEPENDENT|wazuh.indexer.node.disk.available[{#NODE.NAME}]|
|Node [{#NODE.NAME}]: Disk usage|Used disk space of the data paths, in %. Calculated from total and available bytes, as the disk watermarks are.|DEPENDENT|wazuh.indexer.node.disk.util[{#NODE.NAME}]|
|Node [{#NODE.NAME}]: File descriptors usage|Open file descriptors, in % of the process limit.|DEPENDENT|wazuh.indexer.node.fd.util[{#NODE.NAME}]|
|Node [{#NODE.NAME}]: Write rejections per second|Rejected tasks of the write thread pool. Rejected bulk requests mean dropped alerts unless the shipper retries.|DEPENDENT|wazuh.indexer.node.write.rejected.rate[{#NODE.NAME}]|
|Node [{#NODE.NAME}]: Search rejections per second|Rejected tasks of the search thread pool.|DEPENDENT|wazuh.indexer.node.search.rejected.rate[{#NODE.NAME}]|
|Node [{#NODE.NAME}]: Parent breaker trips per second|Trips of the parent circuit breaker. A trip rejects the request to protect the JVM heap.|DEPENDENT|wazuh.indexer.node.breaker.tripped.rate[{#NODE.NAME}]|

#### Trigger prototypes for Nodes discovery

|Name|Description|Priority|
|----|-----------|--------|
|Wazuh indexer: Node [{#NODE.NAME}]: JVM heap usage is high|JVM heap usage is above the threshold for one hour.|WARNING|
|Wazuh indexer: Node [{#NODE.NAME}]: JVM heap usage is critical|JVM heap usage is close to the limit. The node can trip circuit breakers or run out of memory.|HIGH|
|Wazuh indexer: Node [{#NODE.NAME}]: Has been restarted|The JVM of the node started less than 10 minutes ago.|INFO|
|Wazuh indexer: Node [{#NODE.NAME}]: Disk usage is over the low watermark|OpenSearch no longer allocates new shards to the node.|WARNING|
|Wazuh indexer: Node [{#NODE.NAME}]: Disk usage is over the high watermark|OpenSearch moves shards away from the node.|AVERAGE|
|Wazuh indexer: Node [{#NODE.NAME}]: Disk usage is over the flood stage watermark|OpenSearch sets a read-only block on every index with a shard on the node. Alerts are no longer indexed in these indices.|HIGH|
|Wazuh indexer: Node [{#NODE.NAME}]: File descriptors usage is high|The node is close to the open files limit of the process.|WARNING|
|Wazuh indexer: Node [{#NODE.NAME}]: Write requests are rejected|The write thread pool queue is full and the node rejects indexing requests.|WARNING|
|Wazuh indexer: Node [{#NODE.NAME}]: Parent circuit breaker trips|The parent circuit breaker rejects requests because the JVM heap is close to its limit.|WARNING|

## Author

Created by Adam "tick" Pielak, [wazuh.blog](https://wazuh.blog).
