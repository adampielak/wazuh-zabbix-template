// Author: Adam "tick" Pielak, https://wazuh.blog
// Wazuh dashboard by HTTP.
// Data source: status API of OpenSearch Dashboards (GET /api/status), on which the
// Wazuh dashboard is built.

import { COLOR, heartbeat, js, jsonpath, multiplier, type ItemDef, type TemplateDef } from "./lib.ts";

export const DASHBOARD = "Wazuh dashboard by HTTP";
const T = DASHBOARD;
const NET = '"{$WAZUH.DASHBOARD.SCHEME}","{$WAZUH.DASHBOARD.HOST}","{$WAZUH.DASHBOARD.PORT}"';
const MASTER = "wazuh.dashboard.get_status";

const STATE_JS = `var state = ['green', 'yellow', 'red'];

return state.indexOf(value.trim()) === -1 ? 255 : state.indexOf(value.trim());`;

const dep = (name: string, key: string, path: string, description: string, component: string, o: Partial<ItemDef> = {}): ItemDef => ({
  name,
  key,
  type: "DEPENDENT",
  description,
  master: MASTER,
  tags: [["component", component]],
  ...o,
  preprocessing: [jsonpath(path), ...(o.preprocessing ?? [])],
});

export const dashboard: TemplateDef = {
  name: T,
  target: "wazuh",
  description: `Monitors the Wazuh dashboard (OpenSearch Dashboards) through its status API: overall state, state of each plugin, Node.js heap, event loop delay, response times and uptime.

Setup:

1. Link the template to a host and set {$WAZUH.DASHBOARD.HOST} to the Wazuh dashboard node.
2. Set {$WAZUH.DASHBOARD.USER} and {$WAZUH.DASHBOARD.PASSWORD} to a Wazuh indexer user. With the security plugin enabled, GET /api/status requires authentication; any user that can log in to the dashboard is sufficient.
3. Change {$WAZUH.DASHBOARD.PORT} if the dashboard does not listen on 443.

Certificates are not verified: the HTTP agent item does not set "verify_peer" and "verify_host".

Tested with Wazuh dashboard 4.14 (OpenSearch Dashboards 2.19) and Zabbix 7.0.`,
  macros: [
    { macro: "{$WAZUH.DASHBOARD.SCHEME}", value: "https", description: "Wazuh dashboard scheme (http or https)." },
    { macro: "{$WAZUH.DASHBOARD.HOST}", value: "<SET WAZUH DASHBOARD HOST>", description: "Hostname or IP address of the Wazuh dashboard." },
    { macro: "{$WAZUH.DASHBOARD.PORT}", value: "443", description: "Wazuh dashboard port." },
    { macro: "{$WAZUH.DASHBOARD.USER}", value: "", description: "User for the status API." },
    { macro: "{$WAZUH.DASHBOARD.PASSWORD}", secret: true, description: "Password of the status API user." },
    { macro: "{$WAZUH.DASHBOARD.RESPONSE_TIME.MAX.WARN}", value: "10s", description: "Maximum response time of the dashboard port for the trigger expression." },
    { macro: "{$WAZUH.DASHBOARD.HEAP.MAX.WARN}", value: "90", description: "Warning threshold of Node.js heap usage, in % of the heap size limit." },
    { macro: "{$WAZUH.DASHBOARD.LLD.FILTER.PLUGIN.MATCHES}", value: ".*", description: "Filter of discoverable plugins by status ID." },
    { macro: "{$WAZUH.DASHBOARD.LLD.FILTER.PLUGIN.NOT_MATCHES}", value: "CHANGE_IF_NEEDED", description: "Filter to exclude discovered plugins by status ID." },
  ],
  valuemaps: [
    { name: "Service state", map: [["0", "Down"], ["1", "Up"]] },
    { name: "Wazuh dashboard state", map: [["0", "green"], ["1", "yellow"], ["2", "red"], ["255", "unknown"]] },
  ],
  items: [
    {
      name: "Service status",
      key: `net.tcp.service[${NET}]`,
      type: "SIMPLE",
      description: "Checks if the dashboard port is accepting TCP connections.",
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
    {
      name: "Get status",
      key: MASTER,
      type: "HTTP_AGENT",
      delay: "1m",
      history: "0",
      value_type: "TEXT",
      description: "Returns the state and metrics of the dashboard. The API answers 503 when the overall state is red.",
      tags: [["component", "raw"]],
      extra: {
        authtype: "BASIC",
        username: "{$WAZUH.DASHBOARD.USER}",
        password: "{$WAZUH.DASHBOARD.PASSWORD}",
        timeout: "15s",
        url: "{$WAZUH.DASHBOARD.SCHEME}://{$WAZUH.DASHBOARD.HOST}:{$WAZUH.DASHBOARD.PORT}/api/status",
        status_codes: "200,503",
      },
    },
    dep("Overall state", "wazuh.dashboard.state", "$.status.overall.state", "Overall state of the dashboard: the worst state of all plugins.", "health", {
      valuemap: "Wazuh dashboard state",
      preprocessing: [js(STATE_JS), heartbeat("1h")],
    }),
    dep("Version", "wazuh.dashboard.version", "$.version.number", "OpenSearch Dashboards version.", "application", {
      value_type: "CHAR",
      preprocessing: [heartbeat("1d")],
    }),
    dep("Uptime", "wazuh.dashboard.uptime", "$.metrics.process.uptime_in_millis", "Time since the Node.js process started.", "application", {
      units: "uptime",
      preprocessing: [js("return Math.floor(value / 1000);")],
    }),
    dep("Heap used", "wazuh.dashboard.heap.used", "$.metrics.process.memory.heap.used_in_bytes", "Node.js heap in use.", "memory", { units: "B" }),
    dep("Heap size limit", "wazuh.dashboard.heap.limit", "$.metrics.process.memory.heap.size_limit", "Maximum Node.js heap size.", "memory", {
      units: "B",
      preprocessing: [heartbeat("1d")],
    }),
    dep("Heap usage", "wazuh.dashboard.heap.util", "$.metrics.process.memory.heap", "Node.js heap in use, in % of the heap size limit.", "memory", {
      value_type: "FLOAT",
      units: "%",
      preprocessing: [
        js(`var heap = JSON.parse(value);

return Math.round(heap.used_in_bytes / heap.size_limit * 10000) / 100;`),
      ],
    }),
    dep("Event loop delay", "wazuh.dashboard.event_loop_delay", "$.metrics.process.event_loop_delay", "Node.js event loop delay. A high delay makes the dashboard slow for every user.", "performance", {
      value_type: "FLOAT",
      units: "s",
      preprocessing: [multiplier("0.001")],
    }),
    dep("Response time, avg", "wazuh.dashboard.response_time.avg", "$.metrics.response_times.avg_in_millis", "Average response time of HTTP requests in the last collection interval of the dashboard.", "performance", {
      value_type: "FLOAT",
      units: "s",
      preprocessing: [multiplier("0.001")],
    }),
    dep("Response time, max", "wazuh.dashboard.response_time.max", "$.metrics.response_times.max_in_millis", "Maximum response time of HTTP requests in the last collection interval of the dashboard.", "performance", {
      value_type: "FLOAT",
      units: "s",
      preprocessing: [multiplier("0.001")],
    }),
    dep("Concurrent connections", "wazuh.dashboard.connections", "$.metrics.concurrent_connections", "Open HTTP connections.", "connections"),
  ],
  rules: [
    {
      name: "Plugins discovery",
      key: "wazuh.dashboard.plugin.discovery",
      type: "DEPENDENT",
      master: MASTER,
      description: "Discovers the core services and plugins listed by the status API.",
      filter: [
        { macro: "{#PLUGIN}", value: "{$WAZUH.DASHBOARD.LLD.FILTER.PLUGIN.MATCHES}" },
        { macro: "{#PLUGIN}", value: "{$WAZUH.DASHBOARD.LLD.FILTER.PLUGIN.NOT_MATCHES}", operator: "NOT_MATCHES_REGEX" },
      ],
      preprocessing: [
        js(`var data = JSON.parse(value);

if (!data.status || !Array.isArray(data.status.statuses)) {
	throw 'No status data.';
}

// Status IDs carry the version ("plugin:name@2.19.6"); strip it so that items survive upgrades.
// The ID is placed into the item prototype script, so only IDs made of safe characters are discovered.
return JSON.stringify(data.status.statuses.map(function (status) {
	return String(status.id).replace(/@[^@]*$/, '');
}).filter(function (id) {
	return /^[A-Za-z0-9:_.-]+$/.test(id);
}).map(function (id) {
	return {'{#PLUGIN}': id};
}));`, ["DISCARD_VALUE"]),
        heartbeat("1h"),
      ],
      items: [
        {
          name: "Plugin [{#PLUGIN}]: State",
          key: "wazuh.dashboard.plugin.state[{#PLUGIN}]",
          type: "DEPENDENT",
          master: MASTER,
          valuemap: "Wazuh dashboard state",
          description: "State of the plugin or core service.",
          preprocessing: [
            js(`var data = JSON.parse(value),
	id = '{#PLUGIN}',
	state = ['green', 'yellow', 'red'],
	found = data.status.statuses.filter(function (status) {
		return status.id.replace(/@[^@]*$/, '') === id;
	});

if (found.length === 0) {
	throw 'Plugin ' + id + ' is not listed.';
}

return state.indexOf(found[0].state) === -1 ? 255 : state.indexOf(found[0].state);`),
            heartbeat("1h"),
          ],
          tags: [["component", "plugin"], ["plugin", "{#PLUGIN}"]],
        },
      ],
    },
  ],
  triggers: [
    {
      name: "Wazuh dashboard: Service is down",
      expression: `last(/${T}/net.tcp.service[${NET}])=0`,
      priority: "AVERAGE",
      manual_close: true,
      description: "The dashboard port is not accepting TCP connections.",
      scope: "availability",
    },
    {
      name: "Wazuh dashboard: Service response time is too high",
      event_name: "Wazuh dashboard: Service response time is too high (over {$WAZUH.DASHBOARD.RESPONSE_TIME.MAX.WARN} for 5m)",
      expression: `min(/${T}/net.tcp.service.perf[${NET}],5m)>{$WAZUH.DASHBOARD.RESPONSE_TIME.MAX.WARN}`,
      priority: "WARNING",
      manual_close: true,
      description: "The TCP service of the dashboard responds slowly.",
      depends: ["Wazuh dashboard: Service is down"],
      scope: "performance",
    },
    {
      name: "Wazuh dashboard: Failed to fetch status",
      event_name: "Wazuh dashboard: Failed to fetch status (or no data for 30m)",
      expression: `nodata(/${T}/wazuh.dashboard.state,30m)=1`,
      priority: "WARNING",
      manual_close: true,
      description: "The status API returned no data for 30 minutes. Check the \"Get status\" item error and the API credentials.",
      depends: ["Wazuh dashboard: Service is down"],
      scope: "availability",
    },
    {
      name: "Wazuh dashboard: State is RED",
      expression: `last(/${T}/wazuh.dashboard.state)=2`,
      priority: "HIGH",
      description: "At least one core service or plugin is red. The dashboard is not usable. A red \"core:opensearch\" means the dashboard cannot reach the Wazuh indexer.",
      scope: "availability",
    },
    {
      name: "Wazuh dashboard: State is YELLOW",
      expression: `last(/${T}/wazuh.dashboard.state)=1`,
      priority: "AVERAGE",
      description: "At least one core service or plugin is degraded.",
      depends: ["Wazuh dashboard: State is RED"],
      scope: "availability",
    },
    {
      name: "Wazuh dashboard: Version has changed",
      expression: `last(/${T}/wazuh.dashboard.version,#1)<>last(/${T}/wazuh.dashboard.version,#2) and length(last(/${T}/wazuh.dashboard.version))>0`,
      priority: "INFO",
      manual_close: true,
      description: "The dashboard version has changed. Acknowledge to close the problem manually.",
      scope: "notice",
    },
    {
      name: "Wazuh dashboard: Has been restarted",
      event_name: "Wazuh dashboard: Has been restarted (uptime < 10m)",
      expression: `last(/${T}/wazuh.dashboard.uptime)<10m`,
      priority: "INFO",
      manual_close: true,
      description: "The dashboard process started less than 10 minutes ago.",
      scope: "notice",
    },
    {
      name: "Wazuh dashboard: Heap usage is high",
      event_name: "Wazuh dashboard: Heap usage is high (over {$WAZUH.DASHBOARD.HEAP.MAX.WARN}% for 15m)",
      expression: `min(/${T}/wazuh.dashboard.heap.util,15m)>{$WAZUH.DASHBOARD.HEAP.MAX.WARN}`,
      opdata: "Used: {ITEM.LASTVALUE1}",
      priority: "WARNING",
      description: "The Node.js process is close to the heap size limit and can stop with an out of memory error.",
      scope: "capacity",
    },
    {
      name: "Wazuh dashboard: Plugin [{#PLUGIN}] is not green",
      expression: `last(/${T}/wazuh.dashboard.plugin.state[{#PLUGIN}])<>0`,
      opdata: "State: {ITEM.LASTVALUE1}",
      priority: "WARNING",
      description: "The plugin or core service reports a degraded or failed state.",
      depends: ["Wazuh dashboard: State is RED"],
      scope: "availability",
    },
  ],
  graphs: [
    {
      name: "Wazuh dashboard: Heap",
      items: [
        { key: "wazuh.dashboard.heap.used", color: COLOR.blue },
        { key: "wazuh.dashboard.heap.limit", color: COLOR.red },
      ],
    },
    {
      name: "Wazuh dashboard: Response time",
      items: [
        { key: "wazuh.dashboard.response_time.avg", color: COLOR.green },
        { key: "wazuh.dashboard.response_time.max", color: COLOR.orange },
        { key: "wazuh.dashboard.event_loop_delay", color: COLOR.grey },
      ],
    },
  ],
  dashboards: [
    {
      name: "Wazuh dashboard",
      pages: [
        {
          name: "Overview",
          widgets: [
            { type: "graph", x: 0, y: 0, width: 36, height: 5, graph: "Wazuh dashboard: Heap" },
            { type: "graph", x: 36, y: 0, width: 36, height: 5, graph: "Wazuh dashboard: Response time" },
          ],
        },
      ],
    },
  ],
};
