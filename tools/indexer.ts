// Author: Adam "tick" Pielak, https://wazuh.blog
// Wazuh indexer by HTTP.
// Data source: OpenSearch REST API of the Wazuh indexer
// (https://docs.opensearch.org/latest/api-reference/). Layout follows the official
// "Elasticsearch Cluster by HTTP" template.

import { COLOR, heartbeat, js, jsonpath, multiplier, perSecond, type ItemDef, type TemplateDef } from "./lib.ts";

export const INDEXER = "Wazuh indexer by HTTP";
const T = INDEXER;
const BASE = "{$WAZUH.INDEXER.SCHEME}://{$WAZUH.INDEXER.HOST}:{$WAZUH.INDEXER.PORT}";
const NET = '"{$WAZUH.INDEXER.SCHEME}","{$WAZUH.INDEXER.HOST}","{$WAZUH.INDEXER.PORT}"';
const AUTH = { authtype: "BASIC", username: "{$WAZUH.INDEXER.USER}", password: "{$WAZUH.INDEXER.PASSWORD}" };

const HEALTH = "wazuh.indexer.cluster.get_health";
const SETTINGS = "wazuh.indexer.cluster.get_settings";
const NODES = "wazuh.indexer.nodes.get_stats";
const INFO = "wazuh.indexer.nodes.get_info";
const ALERTS = "wazuh.indexer.alerts.get";

const raw = (name: string, key: string, path: string, description: string, delay: string, extra: object = {}): ItemDef => ({
  name,
  key,
  type: "HTTP_AGENT",
  delay,
  history: "0",
  value_type: "TEXT",
  description,
  tags: [["component", "raw"]],
  extra: { ...AUTH, timeout: "15s", url: BASE + path, ...extra },
});

const dep = (
  master: string,
  name: string,
  key: string,
  path: string,
  description: string,
  component: string,
  o: Partial<ItemDef> = {},
): ItemDef => ({
  name,
  key,
  type: "DEPENDENT",
  description,
  master,
  tags: [["component", component]],
  ...o,
  // An empty path passes the raw master value to the item's own steps.
  preprocessing: [...(path ? [jsonpath(path)] : []), ...(o.preprocessing ?? [])],
});

const NODES_JS = `var data = JSON.parse(value),
	nodes = [];

function pct(part, total) {
	return (total > 0) ? Math.round(part / total * 10000) / 100 : 0;
}

Object.keys(data.nodes || {}).forEach(function (id) {
	var node = data.nodes[id],
		fs = (node.fs || {}).total || {},
		process = node.process || {},
		pools = node.thread_pool || {};

	nodes.push({
		name: node.name,
		roles: (node.roles || []).join(','),
		heap_pct: node.jvm.mem.heap_used_percent,
		uptime: Math.floor(node.jvm.uptime_in_millis / 1000),
		cpu_pct: node.os.cpu.percent,
		disk_total: fs.total_in_bytes,
		disk_available: fs.available_in_bytes,
		disk_pct: pct(fs.total_in_bytes - fs.available_in_bytes, fs.total_in_bytes),
		fd_pct: pct(process.open_file_descriptors, process.max_file_descriptors),
		write_rejected: (pools.write || {}).rejected,
		search_rejected: (pools.search || {}).rejected,
		breaker_tripped: ((node.breakers || {}).parent || {}).tripped
	});
});

return JSON.stringify(nodes);`;

// Effective value of a setting: transient > persistent > defaults, as applied by OpenSearch.
const setting = (path: string, watermark: boolean) => `var data = JSON.parse(value),
	value = null;

['transient', 'persistent', 'defaults'].some(function (scope) {
	var node = data[scope];

	'${path}'.split('.').forEach(function (key) {
		node = (node !== undefined && node !== null) ? node[key] : undefined;
	});
	if (node !== undefined && node !== null) {
		value = String(node);

		return true;
	}

	return false;
});

if (value === null) {
	throw 'Setting ${path} is not set.';
}
${
  watermark
    ? `
// A watermark is a percentage ("85%"), a ratio ("0.85") or an absolute free space ("10gb").
// Absolute values are returned as -1: the disk triggers use only relative watermarks.
if (/^\\d+(\\.\\d+)?%$/.test(value)) {
	return parseFloat(value);
}
if (/^0?\\.\\d+$|^1(\\.0+)?$/.test(value)) {
	return parseFloat(value) * 100;
}

return -1;`
    : `
return parseInt(value, 10);`
}`;

const node = (name: string, key: string, field: string, description: string, component: string, o: Partial<ItemDef> = {}): ItemDef => ({
  name: `Node [{#NODE.NAME}]: ${name}`,
  key: `${key}[{#NODE.NAME}]`,
  type: "DEPENDENT",
  master: "wazuh.indexer.node.get[{#NODE.NAME}]",
  description,
  tags: [["component", component], ["node", "{#NODE.NAME}"]],
  ...o,
  preprocessing: [jsonpath(`$.${field}`), ...(o.preprocessing ?? [])],
});

const wm = (level: string, title: string, priority: "WARNING" | "AVERAGE" | "HIGH", text: string, depends?: string) => ({
  name: `Wazuh indexer: Node [{#NODE.NAME}]: Disk usage is over the ${title} watermark`,
  expression: `min(/${T}/wazuh.indexer.node.disk.util[{#NODE.NAME}],5m)>last(/${T}/wazuh.indexer.watermark.${level}) and last(/${T}/wazuh.indexer.watermark.${level})>0`,
  opdata: "Used: {ITEM.LASTVALUE1}, watermark: {ITEM.LASTVALUE2}",
  priority,
  description: text,
  depends: depends ? [depends] : undefined,
  scope: "capacity" as const,
});

export const indexer: TemplateDef = {
  name: T,
  target: "wazuh",
  description: `Monitors the Wazuh indexer (OpenSearch) cluster through its REST API: cluster health, shard allocation and limits, disk watermarks, per-node JVM heap, disk, CPU, file descriptors, thread pool rejections, circuit breakers, and the ingest of Wazuh alerts.

Setup:

1. Create an indexer user for monitoring. It needs the cluster permission cluster_monitor and the index permission indices:data/read/search on the alerts index pattern (wazuh-alerts-* by default). The README in the repository root has an example role.
2. Link the template to a host and set {$WAZUH.INDEXER.HOST} to one indexer node, or to a load balancer in front of the cluster. All cluster data is collected through this node, so link the template to one host per cluster.
3. Set {$WAZUH.INDEXER.USER} and {$WAZUH.INDEXER.PASSWORD}.

The Wazuh indexer uses https on port 9200 by default. Certificates are not verified: the HTTP agent items do not set "verify_peer" and "verify_host".

Tested with Wazuh indexer 4.14 (OpenSearch 2.19) and Zabbix 7.0.`,
  macros: [
    { macro: "{$WAZUH.INDEXER.SCHEME}", value: "https", description: "Wazuh indexer REST API scheme (http or https)." },
    { macro: "{$WAZUH.INDEXER.HOST}", value: "<SET WAZUH INDEXER HOST>", description: "Hostname or IP address of a Wazuh indexer node." },
    { macro: "{$WAZUH.INDEXER.PORT}", value: "9200", description: "Wazuh indexer REST API port." },
    { macro: "{$WAZUH.INDEXER.USER}", value: "", description: "Wazuh indexer user with the cluster_monitor permission." },
    { macro: "{$WAZUH.INDEXER.PASSWORD}", secret: true, description: "Password of the Wazuh indexer user." },
    { macro: "{$WAZUH.INDEXER.RESPONSE_TIME.MAX.WARN}", value: "10s", description: "Maximum response time of the indexer port for the trigger expression." },
    { macro: "{$WAZUH.INDEXER.HEAP.MAX.WARN}", value: "85", description: "Warning threshold of JVM heap usage, in %." },
    { macro: "{$WAZUH.INDEXER.HEAP.MAX.CRIT}", value: "95", description: "Critical threshold of JVM heap usage, in %." },
    { macro: "{$WAZUH.INDEXER.FD.MAX.WARN}", value: "90", description: "Warning threshold of open file descriptors, in % of the limit." },
    { macro: "{$WAZUH.INDEXER.SHARDS.MAX.WARN}", value: "90", description: "Warning threshold of shards in use, in % of cluster.max_shards_per_node multiplied by the data nodes." },
    { macro: "{$WAZUH.INDEXER.ALERTS.INDEX}", value: "wazuh-alerts-*", description: "Index pattern of the Wazuh alerts." },
    { macro: "{$WAZUH.INDEXER.ALERTS.WINDOW}", value: "10m", description: "Time window for counting indexed alerts, in OpenSearch date math units (m, h, d)." },
  ],
  valuemaps: [
    { name: "Service state", map: [["0", "Down"], ["1", "Up"]] },
    { name: "Wazuh indexer cluster state", map: [["0", "green"], ["1", "yellow"], ["2", "red"], ["255", "unknown"]] },
  ],
  items: [
    {
      name: "Service status",
      key: `net.tcp.service[${NET}]`,
      type: "SIMPLE",
      description: "Checks if the indexer port is accepting TCP connections.",
      valuemap: "Service state",
      preprocessing: [heartbeat("10m")],
      tags: [["component", "health"], ["component", "network"]],
    },
    {
      name: "Service response time",
      key: `net.tcp.service.perf[${NET}]`,
      type: "SIMPLE",
      value_type: "FLOAT",
      units: "s",
      description: "Checks the performance of the TCP service.",
      tags: [["component", "network"]],
    },
    raw(
      "Get cluster health",
      HEALTH,
      "/_cluster/health?timeout=5s",
      "Returns the health of the cluster.",
      "1m",
    ),
    raw(
      "Get cluster settings",
      SETTINGS,
      "/_cluster/settings?include_defaults=true&filter_path=*.cluster.max_shards_per_node,*.cluster.routing.allocation.disk.watermark",
      "Returns the shard limit and the disk watermarks (transient, persistent and default values).",
      "1h",
    ),
    raw(
      "Get nodes stats",
      NODES,
      "/_nodes/stats/jvm,fs,os,process,thread_pool,breaker?filter_path=nodes.*.name,nodes.*.roles,nodes.*.jvm.mem.heap_used_percent,nodes.*.jvm.uptime_in_millis,nodes.*.fs.total,nodes.*.os.cpu.percent,nodes.*.process.open_file_descriptors,nodes.*.process.max_file_descriptors,nodes.*.thread_pool.write.rejected,nodes.*.thread_pool.search.rejected,nodes.*.breakers.parent.tripped",
      "Returns statistics of all cluster nodes.",
      "1m",
      { timeout: "30s" },
    ),
    raw("Get nodes info", INFO, "/_nodes?filter_path=nodes.*.name,nodes.*.version", "Returns the name and version of all cluster nodes.", "1h"),
    raw(
      "Get alerts ingest",
      ALERTS,
      "/{$WAZUH.INDEXER.ALERTS.INDEX}/_search?size=0&filter_path=hits.total,aggregations",
      "Counts the alerts indexed in the last {$WAZUH.INDEXER.ALERTS.WINDOW} and returns the newest alert timestamp.",
      "5m",
      {
        request_method: "POST",
        post_type: "JSON",
        posts:
          '{"track_total_hits":true,"query":{"range":{"timestamp":{"gte":"now-{$WAZUH.INDEXER.ALERTS.WINDOW}"}}},"aggs":{"last":{"max":{"field":"timestamp"}}}}',
      },
    ),

    // Cluster health
    dep(HEALTH, "Cluster health status", "wazuh.indexer.cluster.status", "$.status", "Health of the cluster: green - all shards are assigned, yellow - all primary shards are assigned but one or more replicas are not, red - one or more primary shards are not assigned.", "health", {
      valuemap: "Wazuh indexer cluster state",
      preprocessing: [
        js(`var state = ['green', 'yellow', 'red'];

return state.indexOf(value.trim()) === -1 ? 255 : state.indexOf(value.trim());`),
        heartbeat("1h"),
      ],
    }),
    dep(HEALTH, "Cluster name", "wazuh.indexer.cluster.name", "$.cluster_name", "Name of the cluster.", "health", {
      value_type: "CHAR",
      preprocessing: [heartbeat("1d")],
    }),
    dep(HEALTH, "Number of nodes", "wazuh.indexer.nodes.number", "$.number_of_nodes", "Nodes in the cluster.", "health", { preprocessing: [heartbeat("1h")] }),
    dep(HEALTH, "Number of data nodes", "wazuh.indexer.nodes.data", "$.number_of_data_nodes", "Data nodes in the cluster.", "health", { preprocessing: [heartbeat("1h")] }),
    dep(HEALTH, "Active primary shards", "wazuh.indexer.shards.primary", "$.active_primary_shards", "Active primary shards.", "shards"),
    dep(HEALTH, "Active shards", "wazuh.indexer.shards.active", "$.active_shards", "Active primary and replica shards.", "shards"),
    dep(HEALTH, "Relocating shards", "wazuh.indexer.shards.relocating", "$.relocating_shards", "Shards that are moving to another node.", "shards"),
    dep(HEALTH, "Initializing shards", "wazuh.indexer.shards.initializing", "$.initializing_shards", "Shards that are being initialized.", "shards"),
    dep(HEALTH, "Unassigned shards", "wazuh.indexer.shards.unassigned", "$.unassigned_shards", "Shards that are not allocated to a node.", "shards"),
    dep(HEALTH, "Delayed unassigned shards", "wazuh.indexer.shards.delayed_unassigned", "$.delayed_unassigned_shards", "Shards whose allocation is delayed by the timeout settings.", "shards"),
    dep(HEALTH, "Active shards, in %", "wazuh.indexer.shards.active.pct", "$.active_shards_percent_as_number", "Ratio of active shards to all shards.", "shards", {
      value_type: "FLOAT",
      units: "%",
    }),
    dep(HEALTH, "Pending tasks", "wazuh.indexer.cluster.pending_tasks", "$.number_of_pending_tasks", "Cluster-level changes that are not yet executed.", "health"),

    // Settings
    dep(SETTINGS, "Max shards per node", "wazuh.indexer.max_shards_per_node", "", "Effective value of cluster.max_shards_per_node.", "shards", {
      preprocessing: [js(setting("cluster.max_shards_per_node", false)), heartbeat("1d")],
    }),
    ...(
      [
        ["low", "low", "Above the low watermark OpenSearch stops allocating new shards to the node."],
        ["high", "high", "Above the high watermark OpenSearch moves shards away from the node."],
        ["flood", "flood_stage", "Above the flood-stage watermark OpenSearch sets a read-only block on every index with a shard on the node. Wazuh alerts are then no longer indexed."],
      ] as const
    ).map(
      ([k, s, d]): ItemDef =>
        dep(SETTINGS, `Disk watermark ${s.replace("_", " ")}`, `wazuh.indexer.watermark.${k}`, "", `Effective value of cluster.routing.allocation.disk.watermark.${s}, in % of used disk space. -1 when the watermark is an absolute value. ${d}`, "storage", {
          value_type: "FLOAT",
          units: "%",
          preprocessing: [js(setting(`cluster.routing.allocation.disk.watermark.${s}`, true)), heartbeat("1d")],
        }),
    ),
    {
      name: "Shards in use, in % of the limit",
      key: "wazuh.indexer.shards.limit.util",
      type: "CALCULATED",
      delay: "1m",
      value_type: "FLOAT",
      units: "%",
      description: "Active and unassigned shards in % of the cluster shard limit (cluster.max_shards_per_node multiplied by the data nodes). New indices cannot be created when the limit is reached, so Wazuh stops indexing alerts at the next daily index rollover.",
      tags: [["component", "shards"]],
      extra: {
        params:
          "100*(last(//wazuh.indexer.shards.active)+last(//wazuh.indexer.shards.unassigned))/(last(//wazuh.indexer.max_shards_per_node)*last(//wazuh.indexer.nodes.data))",
      },
    },

    // Versions
    dep(INFO, "Version", "wazuh.indexer.version", "$..version.first()", "OpenSearch version of the first node in the nodes info response.", "application", {
      value_type: "CHAR",
      preprocessing: [heartbeat("1d")],
    }),

    // Alerts ingest
    dep(ALERTS, "Alerts indexed", "wazuh.indexer.alerts.count", "$.hits.total.value", "Alerts indexed in the last {$WAZUH.INDEXER.ALERTS.WINDOW}.", "alerts"),
    dep(ALERTS, "Newest alert time", "wazuh.indexer.alerts.last", "$.aggregations.last.value", "Timestamp of the newest alert in the alerts index. No value when no alert was indexed in the time window.", "alerts", {
      units: "unixtime",
      preprocessing: [multiplier("0.001")],
    }),
  ],
  rules: [
    {
      name: "Nodes discovery",
      key: "wazuh.indexer.nodes.discovery",
      type: "DEPENDENT",
      master: NODES,
      description: "Discovers the nodes of the indexer cluster.",
      preprocessing: [js(NODES_JS), heartbeat("1h")],
      extra: {
        lld_macro_paths: [
          { lld_macro: "{#NODE.NAME}", path: "$.name" },
          { lld_macro: "{#NODE.ROLES}", path: "$.roles" },
        ],
      },
      items: [
        {
          name: "Node [{#NODE.NAME}]: Get data",
          key: "wazuh.indexer.node.get[{#NODE.NAME}]",
          type: "DEPENDENT",
          master: NODES,
          history: "0",
          value_type: "TEXT",
          description: "Normalized statistics of the node.",
          preprocessing: [js(NODES_JS), jsonpath("$[?(@.name=='{#NODE.NAME}')].first()")],
          tags: [["component", "raw"], ["node", "{#NODE.NAME}"]],
        },
        node("JVM heap usage", "wazuh.indexer.node.heap.util", "heap_pct", "Used JVM heap, in % of the maximum heap.", "memory", { units: "%" }),
        node("Uptime", "wazuh.indexer.node.uptime", "uptime", "Time since the JVM of the node started.", "application", { units: "uptime" }),
        node("CPU usage", "wazuh.indexer.node.cpu.util", "cpu_pct", "CPU usage of the node host, as reported by OpenSearch.", "cpu", { units: "%" }),
        node("Disk total", "wazuh.indexer.node.disk.total", "disk_total", "Total size of the data paths.", "storage", { units: "B", preprocessing: [heartbeat("1d")] }),
        node("Disk available", "wazuh.indexer.node.disk.available", "disk_available", "Disk space available to OpenSearch on the data paths.", "storage", { units: "B" }),
        node("Disk usage", "wazuh.indexer.node.disk.util", "disk_pct", "Used disk space of the data paths, in %. Calculated from total and available bytes, as the disk watermarks are.", "storage", {
          value_type: "FLOAT",
          units: "%",
        }),
        node("File descriptors usage", "wazuh.indexer.node.fd.util", "fd_pct", "Open file descriptors, in % of the process limit.", "os", { value_type: "FLOAT", units: "%" }),
        node("Write rejections per second", "wazuh.indexer.node.write.rejected.rate", "write_rejected", "Rejected tasks of the write thread pool. Rejected bulk requests mean dropped alerts unless the shipper retries.", "performance", {
          value_type: "FLOAT",
          units: "rps",
          preprocessing: [perSecond()],
        }),
        node("Search rejections per second", "wazuh.indexer.node.search.rejected.rate", "search_rejected", "Rejected tasks of the search thread pool.", "performance", {
          value_type: "FLOAT",
          units: "rps",
          preprocessing: [perSecond()],
        }),
        node("Parent breaker trips per second", "wazuh.indexer.node.breaker.tripped.rate", "breaker_tripped", "Trips of the parent circuit breaker. A trip rejects the request to protect the JVM heap.", "memory", {
          value_type: "FLOAT",
          preprocessing: [perSecond()],
        }),
      ],
      graphs: [
        {
          name: "Wazuh indexer: Node [{#NODE.NAME}]: Disk usage",
          items: [{ key: "wazuh.indexer.node.disk.util[{#NODE.NAME}]", color: COLOR.blue }],
        },
        {
          name: "Wazuh indexer: Node [{#NODE.NAME}]: Rejections",
          items: [
            { key: "wazuh.indexer.node.write.rejected.rate[{#NODE.NAME}]", color: COLOR.red },
            { key: "wazuh.indexer.node.search.rejected.rate[{#NODE.NAME}]", color: COLOR.orange },
            { key: "wazuh.indexer.node.breaker.tripped.rate[{#NODE.NAME}]", color: COLOR.yellow },
          ],
        },
        {
          name: "Wazuh indexer: Node [{#NODE.NAME}]: JVM heap and CPU",
          items: [
            { key: "wazuh.indexer.node.heap.util[{#NODE.NAME}]", color: COLOR.green },
            { key: "wazuh.indexer.node.cpu.util[{#NODE.NAME}]", color: COLOR.blue },
          ],
        },
      ],
    },
  ],
  triggers: [
    {
      name: "Wazuh indexer: Service is down",
      expression: `last(/${T}/net.tcp.service[${NET}])=0`,
      priority: "AVERAGE",
      description: "The indexer port is not accepting TCP connections.",
      manual_close: true,
      scope: "availability",
    },
    {
      name: "Wazuh indexer: Service response time is too high",
      event_name: "Wazuh indexer: Service response time is too high (over {$WAZUH.INDEXER.RESPONSE_TIME.MAX.WARN} for 5m)",
      expression: `min(/${T}/net.tcp.service.perf[${NET}],5m)>{$WAZUH.INDEXER.RESPONSE_TIME.MAX.WARN}`,
      priority: "WARNING",
      description: "The TCP service of the indexer responds slowly.",
      manual_close: true,
      depends: ["Wazuh indexer: Service is down"],
      scope: "performance",
    },
    {
      name: "Wazuh indexer: Health is RED",
      expression: `last(/${T}/wazuh.indexer.cluster.status)=2`,
      priority: "HIGH",
      description: "One or more primary shards are unassigned. Some data is unavailable and new alerts for the affected indices are not indexed.",
      scope: "availability",
    },
    {
      name: "Wazuh indexer: Health is YELLOW",
      expression: `last(/${T}/wazuh.indexer.cluster.status)=1`,
      priority: "AVERAGE",
      description: "All primary shards are assigned, but one or more replica shards are not. If a node fails, some data can be unavailable until the node is repaired.",
      scope: "availability",
    },
    {
      name: "Wazuh indexer: Health is UNKNOWN",
      expression: `last(/${T}/wazuh.indexer.cluster.status)=255`,
      priority: "HIGH",
      description: "The health of the cluster is unknown or cannot be read.",
      scope: "availability",
    },
    {
      name: "Wazuh indexer: Number of nodes has decreased",
      expression: `change(/${T}/wazuh.indexer.nodes.number)<0`,
      priority: "WARNING",
      manual_close: true,
      description: "One or more nodes left the cluster.",
      scope: "availability",
    },
    {
      name: "Wazuh indexer: Shard usage is close to the cluster limit",
      event_name: "Wazuh indexer: Shard usage is close to the cluster limit (over {$WAZUH.INDEXER.SHARDS.MAX.WARN}%)",
      expression: `last(/${T}/wazuh.indexer.shards.limit.util)>{$WAZUH.INDEXER.SHARDS.MAX.WARN}`,
      opdata: "Used: {ITEM.LASTVALUE1}",
      priority: "WARNING",
      description: "When the shard limit is reached, OpenSearch refuses to create new indices and the next daily wazuh-alerts index is not created. Delete old indices, lower the replica count or raise cluster.max_shards_per_node.",
      scope: "capacity",
    },
    {
      name: "Wazuh indexer: No alerts indexed",
      event_name: "Wazuh indexer: No alerts indexed in the last {$WAZUH.INDEXER.ALERTS.WINDOW}",
      expression: `last(/${T}/wazuh.indexer.alerts.count)=0`,
      priority: "HIGH",
      description: "No document was written to {$WAZUH.INDEXER.ALERTS.INDEX} in the time window. Check the Filebeat output on the Wazuh server nodes, the indexer health and the disk watermarks.",
      depends: ["Wazuh indexer: Service is down"],
      scope: "availability",
    },
    {
      name: "Wazuh indexer: Node [{#NODE.NAME}]: JVM heap usage is high",
      event_name: "Wazuh indexer: Node [{#NODE.NAME}]: JVM heap usage is high (over {$WAZUH.INDEXER.HEAP.MAX.WARN}% for 1h)",
      expression: `min(/${T}/wazuh.indexer.node.heap.util[{#NODE.NAME}],1h)>{$WAZUH.INDEXER.HEAP.MAX.WARN}`,
      opdata: "Used: {ITEM.LASTVALUE1}",
      priority: "WARNING",
      description: "JVM heap usage is above the threshold for one hour.",
      depends: ["Wazuh indexer: Node [{#NODE.NAME}]: JVM heap usage is critical"],
      scope: "capacity",
    },
    {
      name: "Wazuh indexer: Node [{#NODE.NAME}]: JVM heap usage is critical",
      event_name: "Wazuh indexer: Node [{#NODE.NAME}]: JVM heap usage is critical (over {$WAZUH.INDEXER.HEAP.MAX.CRIT}% for 1h)",
      expression: `min(/${T}/wazuh.indexer.node.heap.util[{#NODE.NAME}],1h)>{$WAZUH.INDEXER.HEAP.MAX.CRIT}`,
      opdata: "Used: {ITEM.LASTVALUE1}",
      priority: "HIGH",
      description: "JVM heap usage is close to the limit. The node can trip circuit breakers or run out of memory.",
      scope: "capacity",
    },
    {
      name: "Wazuh indexer: Node [{#NODE.NAME}]: Has been restarted",
      event_name: "Wazuh indexer: Node [{#NODE.NAME}]: Has been restarted (uptime < 10m)",
      expression: `last(/${T}/wazuh.indexer.node.uptime[{#NODE.NAME}])<10m`,
      priority: "INFO",
      manual_close: true,
      description: "The JVM of the node started less than 10 minutes ago.",
      scope: "notice",
    },
    wm("low", "low", "WARNING", "OpenSearch no longer allocates new shards to the node.", "Wazuh indexer: Node [{#NODE.NAME}]: Disk usage is over the high watermark"),
    wm("high", "high", "AVERAGE", "OpenSearch moves shards away from the node.", "Wazuh indexer: Node [{#NODE.NAME}]: Disk usage is over the flood stage watermark"),
    wm("flood", "flood stage", "HIGH", "OpenSearch sets a read-only block on every index with a shard on the node. Alerts are no longer indexed in these indices."),
    {
      name: "Wazuh indexer: Node [{#NODE.NAME}]: File descriptors usage is high",
      event_name: "Wazuh indexer: Node [{#NODE.NAME}]: File descriptors usage is high (over {$WAZUH.INDEXER.FD.MAX.WARN}%)",
      expression: `min(/${T}/wazuh.indexer.node.fd.util[{#NODE.NAME}],5m)>{$WAZUH.INDEXER.FD.MAX.WARN}`,
      opdata: "Used: {ITEM.LASTVALUE1}",
      priority: "WARNING",
      description: "The node is close to the open files limit of the process.",
      scope: "capacity",
    },
    {
      name: "Wazuh indexer: Node [{#NODE.NAME}]: Write requests are rejected",
      expression: `min(/${T}/wazuh.indexer.node.write.rejected.rate[{#NODE.NAME}],5m)>0`,
      opdata: "Rate: {ITEM.LASTVALUE1}",
      priority: "WARNING",
      description: "The write thread pool queue is full and the node rejects indexing requests.",
      scope: "performance",
    },
    {
      name: "Wazuh indexer: Node [{#NODE.NAME}]: Parent circuit breaker trips",
      expression: `min(/${T}/wazuh.indexer.node.breaker.tripped.rate[{#NODE.NAME}],5m)>0`,
      opdata: "Rate: {ITEM.LASTVALUE1}",
      priority: "WARNING",
      description: "The parent circuit breaker rejects requests because the JVM heap is close to its limit.",
      scope: "performance",
    },
  ],
  graphs: [
    {
      name: "Wazuh indexer: Shards",
      items: [
        { key: "wazuh.indexer.shards.active", color: COLOR.green },
        { key: "wazuh.indexer.shards.relocating", color: COLOR.blue },
        { key: "wazuh.indexer.shards.initializing", color: COLOR.yellow },
        { key: "wazuh.indexer.shards.unassigned", color: COLOR.red },
      ],
    },
    {
      name: "Wazuh indexer: Alerts indexed",
      items: [{ key: "wazuh.indexer.alerts.count", color: COLOR.orange }],
    },
    {
      name: "Wazuh indexer: Service response time",
      items: [{ key: `net.tcp.service.perf[${NET}]`, color: COLOR.blue }],
    },
  ],
  dashboards: [
    {
      name: "Wazuh indexer",
      pages: [
        {
          name: "Overview",
          widgets: [
            { type: "graph", x: 0, y: 0, width: 36, height: 5, graph: "Wazuh indexer: Alerts indexed" },
            { type: "graph", x: 36, y: 0, width: 36, height: 5, graph: "Wazuh indexer: Shards" },
            { type: "graphprototype", x: 0, y: 5, width: 72, height: 10, graph: "Wazuh indexer: Node [{#NODE.NAME}]: Disk usage", columns: 3, rows: 2 },
            { type: "graphprototype", x: 0, y: 15, width: 72, height: 10, graph: "Wazuh indexer: Node [{#NODE.NAME}]: JVM heap and CPU", columns: 3, rows: 2 },
          ],
        },
      ],
    },
  ],
};
