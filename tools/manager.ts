// Author: Adam "tick" Pielak, https://wazuh.blog
// Wazuh manager by HTTP.
// Data source: Wazuh server API (https://documentation.wazuh.com/current/user-manual/api/reference.html).
// Field semantics verified against api/api/spec/spec.yaml and src/analysisd/state.c,
// src/remoted/state.c of Wazuh v4.14.

import {
  COLOR,
  heartbeat,
  js,
  jsonpath,
  perSecond,
  type ItemDef,
  type TemplateDef,
} from "./lib.ts";

export const MANAGER = "Wazuh manager by HTTP";
const T = MANAGER;
const MASTER = "wazuh.manager.get";

const SCRIPT = `const CTlsConfig = function (raw_value) {
	raw_value = String(raw_value).trim().toLowerCase();

	if (['none', 'peer', 'full'].indexOf(raw_value) === -1) {
		raw_value = 'full';
	}

	this.options = {
		SSLVerifyPeer: (raw_value === 'peer' || raw_value === 'full'),
		SSLVerifyHost: (raw_value === 'full')
	};

	this.enabled = (raw_value !== 'none');

	this.checkURL = function (url) {
		if (this.enabled && !/^https:\\/\\//i.test(url)) {
			throw 'TLS certificate verification is enabled by {$' + 'HTTP.TLS.VERIFY}, but the URL uses plain HTTP: ' + url +
			'. Use an "https://" URL, or set {$' + 'HTTP.TLS.VERIFY} to \`none\` to disable verification.';
		}

		return url;
	};
};

var Wazuh = {
	params: {},
	http: null,
	token: null,

	setParams: function (params) {
		['api_url', 'user', 'password'].forEach(function (field) {
			if (typeof params !== 'object' || typeof params[field] === 'undefined' || params[field] === '') {
				throw 'Required param is not set: "' + field + '".';
			}
		});

		Wazuh.params = params;
		Wazuh.params.api_url = String(params.api_url).replace(/\\/+$/, '');
	},

	init: function () {
		var tls = new CTlsConfig(Wazuh.params.tls_verify);

		tls.checkURL(Wazuh.params.api_url);
		Wazuh.http = new HttpRequest(tls.options);

		if (typeof Wazuh.params.http_proxy === 'string' && Wazuh.params.http_proxy !== '') {
			Wazuh.http.setProxy(Wazuh.params.http_proxy);
		}
	},

	request: function (method, path) {
		var url = Wazuh.params.api_url + path,
			response,
			status,
			detail = '';

		Wazuh.http.clearHeader();
		if (Wazuh.token === null) {
			Wazuh.http.addHeader('Authorization: Basic ' + btoa(Wazuh.params.user + ':' + Wazuh.params.password));
		}
		else {
			Wazuh.http.addHeader('Authorization: Bearer ' + Wazuh.token);
		}

		Zabbix.log(4, '[ Wazuh ] Sending request: ' + method + ' ' + url);
		response = (method === 'POST') ? Wazuh.http.post(url, '') : Wazuh.http.get(url);
		status = Wazuh.http.getStatus();
		Zabbix.log(4, '[ Wazuh ] Received response with status code ' + status + ' for ' + path);

		if (status !== 200) {
			try {
				var body = JSON.parse(response);

				detail = body.detail || body.title || '';
			}
			catch (error) {
				// Not a JSON error body.
			}

			throw 'Request ' + method + ' ' + path + ' failed with status code ' + status + (detail ? ': ' + detail : '') + '.';
		}

		if (response === null || response === '') {
			throw 'Empty response for ' + method + ' ' + path + '.';
		}

		return response;
	},

	get: function (path) {
		var body;

		try {
			body = JSON.parse(Wazuh.request('GET', path));
		}
		catch (error) {
			throw (typeof error === 'string') ? error : 'Failed to parse the response of ' + path + '.';
		}

		if (typeof body.data === 'undefined') {
			throw 'Unexpected response of ' + path + ': no "data" field.';
		}

		return body.data;
	},

	login: function () {
		Wazuh.token = Wazuh.request('POST', '/security/user/authenticate?raw=true');
	}
};

// Wazuh returns timestamps with microseconds; ECMAScript Date.parse accepts milliseconds only.
function parseDate(value) {
	return Date.parse(String(value).replace(/(\\.\\d{3})\\d+/, '$1'));
}

function sumLeaves(object) {
	var total = 0;

	Object.keys(object || {}).forEach(function (key) {
		var value = object[key];

		if (typeof value === 'number') {
			total += value;
		}
		else if (value !== null && typeof value === 'object') {
			total += sumLeaves(value);
		}
	});

	return total;
}

function round(value) {
	return Math.round(value * 100) / 100;
}

var result = {api: {available: 0, version: ''}, error: ''},
	errors = [];

function collect(section, callback) {
	try {
		callback();
	}
	catch (error) {
		errors.push(section + ': ' + error);
		Zabbix.log(3, '[ Wazuh ] Failed to collect "' + section + '": ' + error);
	}
}

Wazuh.setParams(JSON.parse(value));
Wazuh.init();

try {
	Wazuh.login();
	result.api.available = 1;
}
catch (error) {
	result.error = 'login: ' + error;
	Zabbix.log(3, '[ Wazuh ] Login failed: ' + error);

	return JSON.stringify(result);
}

collect('api', function () {
	result.api.version = Wazuh.get('/').api_version;
});

collect('manager', function () {
	var info = Wazuh.get('/manager/info').affected_items[0];

	result.manager = {version: String(info.version).replace(/^v/, ''), type: info.type};
});

collect('daemons', function () {
	var status = Wazuh.get('/manager/status').affected_items[0];

	result.daemons = {};
	Object.keys(status).forEach(function (name) {
		result.daemons[name] = (status[name] === 'running') ? 1 : ((status[name] === 'stopped') ? 0 : 2);
	});
});

collect('stats', function () {
	Wazuh.get('/manager/daemons/stats').affected_items.forEach(function (daemon) {
		var metrics = daemon.metrics || {};

		metrics.uptime = Math.max(0, Math.round((parseDate(daemon.timestamp) - parseDate(daemon.uptime)) / 1000));
		result[String(daemon.name).replace(/^wazuh-/, '')] = metrics;
	});

	if (result.analysisd) {
		var events = result.analysisd.events || {},
			queues = result.analysisd.queues || {};

		events.dropped_total = sumLeaves((events.received_breakdown || {}).dropped_breakdown);
		// analysisd reports queue usage as a ratio (0..1).
		Object.keys(queues).forEach(function (name) {
			queues[name].pct = round(queues[name].usage * 100);
		});
	}

	if (result.remoted && result.remoted.queues && result.remoted.queues.received) {
		var received = result.remoted.queues.received;

		// remoted reports queue usage as a number of messages.
		received.pct = (received.size > 0) ? round(received.usage / received.size * 100) : 0;
	}
});

collect('cluster', function () {
	var status = Wazuh.get('/cluster/status');

	result.cluster = {
		enabled: (status.enabled === 'yes') ? 1 : 0,
		running: (status.running === 'yes') ? 1 : 0,
		name: '',
		node: '',
		role: 'standalone'
	};

	if (result.cluster.running === 1) {
		var local = Wazuh.get('/cluster/local/info').affected_items[0];

		result.cluster.name = local.cluster;
		result.cluster.node = local.node;
		result.cluster.role = local.type;
	}
});

collect('configuration', function () {
	var validation = Wazuh.get('/manager/configuration/validation'),
		valid = (validation.total_failed_items === 0);

	(validation.affected_items || []).forEach(function (node) {
		if (node.status !== 'OK') {
			valid = false;
		}
	});
	result.configuration = {valid: valid ? 1 : 0};
});

// Cluster-wide data is read on the master or on a standalone manager only.
if (result.cluster && result.cluster.role !== 'worker') {
	collect('agents', function () {
		var summary = Wazuh.get('/agents/summary/status'),
			agents = summary.connection;

		agents.not_synced = summary.configuration.not_synced;
		agents.disconnected_pct = (agents.total > 0) ? round(agents.disconnected / agents.total * 100) : 0;
		result.agents = agents;
	});

	collect('updates', function () {
		var check = Wazuh.get('/manager/version/check');

		result.updates = {
			enabled: check.update_check ? 1 : 0,
			latest: (check.last_available_major || {}).tag || (check.last_available_minor || {}).tag
				|| (check.last_available_patch || {}).tag || ''
		};
	});

	result.nodes = [];
	if (result.cluster.running === 1) {
		collect('nodes', function () {
			var now = Date.now();

			result.nodes = Wazuh.get('/cluster/healthcheck').affected_items.map(function (node) {
				var status = node.status || {};

				return {
					name: node.info.name,
					type: node.info.type,
					version: node.info.version,
					active_agents: node.info.n_active_agents,
					keepalive_age: status.last_keep_alive
						? Math.max(0, Math.round((now - parseDate(status.last_keep_alive)) / 1000))
						: null,
					ruleset_synced: null
				};
			});
		});

		collect('ruleset', function () {
			Wazuh.get('/cluster/ruleset/synchronization').affected_items.forEach(function (sync) {
				result.nodes.forEach(function (node) {
					if (node.name === sync.name) {
						node.ruleset_synced = sync.synced ? 1 : 0;
					}
				});
			});
		});
	}
}

result.error = errors.join('\\n');

return JSON.stringify(result);
`;

const lldGuard = `var data = JSON.parse(value);

if (!data.api || data.api.available !== 1) {
	throw 'The Wazuh API is not available.';
}
`;

const dep = (
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
  master: MASTER,
  tags: [["component", component]],
  ...o,
  preprocessing: [jsonpath(path), ...(o.preprocessing ?? [])],
});

const rate = (name: string, key: string, path: string, description: string, component: string, units = "eps"): ItemDef =>
  dep(name, key, path, description, component, { value_type: "FLOAT", units, preprocessing: [perSecond()] });

const proto = { master: MASTER, type: "DEPENDENT" as const };

export const manager: TemplateDef = {
  name: T,
  target: "wazuh",
  description: `Monitors a Wazuh server (manager) node through the Wazuh server API: API availability, daemon states, analysisd and remoted statistics, configuration validation and cluster state.
On the master node or on a standalone manager it also collects agent connection summary, cluster node health, ruleset synchronization and available updates.

Setup:

1. Create a read-only Wazuh API user, for example "zbx_monitor", with read-only policies: manager:read and cluster:status on *:*:*, cluster:read on node:id:*, agent:read on agent:id:*. The README in the repository root has the API calls.
2. Link the template to a host and set {$WAZUH.API.HOST} to the Wazuh server node. Link it to one host per cluster node: node-local data is collected on each node, cluster-wide data on the master only.
3. Set {$WAZUH.API.USER} and {$WAZUH.API.PASSWORD}. Change {$WAZUH.API.SCHEME} and {$WAZUH.API.PORT} if the API does not listen on https:55000.
4. Wazuh generates self-signed certificates by default, so {$HTTP.TLS.VERIFY} defaults to "none". Set it to "full" if the API certificate is trusted by the Zabbix server or proxy.

Tested with Wazuh 4.14 and Zabbix 7.0.`,
  macros: [
    { macro: "{$WAZUH.API.SCHEME}", value: "https", description: "Wazuh server API scheme (http or https)." },
    { macro: "{$WAZUH.API.HOST}", value: "<SET WAZUH API HOST>", description: "Hostname or IP address of the Wazuh server node." },
    { macro: "{$WAZUH.API.PORT}", value: "55000", description: "Wazuh server API port." },
    { macro: "{$WAZUH.API.USER}", value: "zbx_monitor", description: "Wazuh server API user with read-only RBAC permissions." },
    { macro: "{$WAZUH.API.PASSWORD}", secret: true, description: "Password of the Wazuh server API user." },
    { macro: "{$WAZUH.DATA.INTERVAL}", value: "1m", description: "Update interval of the API data item." },
    { macro: "{$WAZUH.HTTP_PROXY}", value: "", description: "HTTP proxy for API requests, for example http://proxy.example.com:3128. Leave empty to connect directly." },
    {
      macro: "{$HTTP.TLS.VERIFY}",
      value: "none",
      description:
        'TLS certificate verification for the script item: "none" - disabled, "peer" - verify the certificate chain and expiration, "full" - full verification. Any other value enables full verification. To override the setting for this template only, define the macro with the context "Wazuh", e.g. {$HTTP.TLS.VERIFY:"Wazuh"}. Requires a Zabbix server or proxy version that supports TLS options in the HttpRequest constructor.',
    },
    { macro: "{$WAZUH.AGENTS.DISCONNECTED.MAX.WARN}", value: "10", description: "Maximum share of disconnected agents, in %, for the trigger expression." },
    { macro: "{$WAZUH.QUEUE.UTIL.MAX.WARN}", value: "80", description: "Warning threshold of analysisd and remoted queue utilization, in %." },
    { macro: "{$WAZUH.QUEUE.UTIL.MAX.CRIT}", value: "95", description: "Critical threshold of analysisd and remoted queue utilization, in %." },
    { macro: "{$WAZUH.CLUSTER.KEEPALIVE.MAX.WARN}", value: "5m", description: "Maximum age of the last keep-alive received by the master from a worker node." },
    { macro: "{$WAZUH.LLD.FILTER.DAEMON.MATCHES}", value: ".*", description: "Filter of discoverable Wazuh daemons by name." },
    { macro: "{$WAZUH.LLD.FILTER.DAEMON.NOT_MATCHES}", value: "CHANGE_IF_NEEDED", description: "Filter to exclude discovered Wazuh daemons by name." },
    {
      macro: "{$WAZUH.DAEMON.OPTIONAL.MATCHES}",
      value: "^wazuh-(agentlessd|csyslogd|dbd|integratord|maild|reportd)$",
      description: "Daemons that run only when enabled in ossec.conf. No \"is not running\" trigger is created for them. Remove a daemon from the list if your configuration requires it.",
    },
  ],
  valuemaps: [
    { name: "Service state", map: [["0", "Down"], ["1", "Up"]] },
    { name: "Wazuh daemon state", map: [["0", "Stopped"], ["1", "Running"], ["2", "Other"]] },
    { name: "Wazuh boolean", map: [["0", "No"], ["1", "Yes"]] },
    { name: "Wazuh configuration status", map: [["0", "Invalid"], ["1", "Valid"]] },
  ],
  items: [
    {
      name: "Get API data",
      key: MASTER,
      type: "SCRIPT",
      delay: "{$WAZUH.DATA.INTERVAL}",
      history: "0",
      value_type: "TEXT",
      description:
        "Logs in to the Wazuh server API and collects manager, daemon, statistics and cluster data in one JSON document. A failed API section is reported in the \"API errors\" item and does not stop the other sections.",
      tags: [["component", "raw"]],
      extra: {
        params: SCRIPT,
        parameters: [
          { name: "api_url", value: "{$WAZUH.API.SCHEME}://{$WAZUH.API.HOST}:{$WAZUH.API.PORT}" },
          { name: "http_proxy", value: "{$WAZUH.HTTP_PROXY}" },
          { name: "password", value: "{$WAZUH.API.PASSWORD}" },
          { name: "tls_verify", value: '{$HTTP.TLS.VERIFY:"Wazuh"}' },
          { name: "user", value: "{$WAZUH.API.USER}" },
        ],
        timeout: "30s",
      },
    },
    dep("API availability", "wazuh.api.available", "$.api.available", "Result of the login to the Wazuh server API: 1 - logged in, 0 - connection or authentication failed.", "health", {
      valuemap: "Service state",
    }),
    dep("API errors", "wazuh.api.errors", "$.error", "Errors returned by the API requests of the last collection. Empty when all requests succeeded.", "health", {
      value_type: "TEXT",
      preprocessing: [heartbeat("1h")],
    }),
    dep("API version", "wazuh.api.version", "$.api.version", "Version of the Wazuh server API.", "application", {
      value_type: "CHAR",
      preprocessing: [heartbeat("1d")],
    }),
    dep("Version", "wazuh.manager.version", "$.manager.version", "Version of the Wazuh manager.", "application", {
      value_type: "CHAR",
      preprocessing: [heartbeat("1d")],
    }),
    dep("Configuration status", "wazuh.manager.config.valid", "$.configuration.valid", "Result of the Wazuh configuration validation (GET /manager/configuration/validation).", "configuration", {
      valuemap: "Wazuh configuration status",
      preprocessing: [heartbeat("1h")],
    }),
    dep("Cluster: Enabled", "wazuh.cluster.enabled", "$.cluster.enabled", "Whether the cluster is enabled in the manager configuration.", "cluster", {
      valuemap: "Wazuh boolean",
      preprocessing: [heartbeat("1h")],
    }),
    dep("Cluster: Running", "wazuh.cluster.running", "$.cluster.running", "Whether the cluster daemon is running.", "cluster", {
      valuemap: "Wazuh boolean",
      preprocessing: [heartbeat("1h")],
    }),
    dep("Cluster: Node role", "wazuh.cluster.role", "$.cluster.role", "Role of this node: master, worker or standalone.", "cluster", {
      value_type: "CHAR",
      preprocessing: [heartbeat("1d")],
    }),
    dep("Cluster: Node name", "wazuh.cluster.node", "$.cluster.node", "Name of this node in the cluster. Empty on a standalone manager.", "cluster", {
      value_type: "CHAR",
      preprocessing: [heartbeat("1d")],
    }),
    dep("Cluster: Name", "wazuh.cluster.name", "$.cluster.name", "Name of the cluster. Empty on a standalone manager.", "cluster", {
      value_type: "CHAR",
      preprocessing: [heartbeat("1d")],
    }),

    // analysisd
    dep("Analysisd: Uptime", "wazuh.analysisd.uptime", "$.analysisd.uptime", "Time since wazuh-analysisd started.", "analysisd", { units: "uptime" }),
    rate("Analysisd: Events received per second", "wazuh.analysisd.events.received.rate", "$.analysisd.events.received", "Events received by wazuh-analysisd.", "analysisd"),
    rate("Analysisd: Events processed per second", "wazuh.analysisd.events.processed.rate", "$.analysisd.events.processed", "Events processed by the rule engine.", "analysisd"),
    rate(
      "Analysisd: Events dropped per second",
      "wazuh.analysisd.events.dropped.rate",
      "$.analysisd.events.dropped_total",
      "Events dropped by wazuh-analysisd because an input queue was full. Sum of all counters in events.received_breakdown.dropped_breakdown.",
      "analysisd",
    ),
    rate("Analysisd: Alerts written per second", "wazuh.analysisd.alerts.written.rate", "$.analysisd.events.written_breakdown.alerts", "Alerts written to alerts.log and alerts.json.", "analysisd"),
    rate("Analysisd: Archives written per second", "wazuh.analysisd.archives.written.rate", "$.analysisd.events.written_breakdown.archives", "Events written to the archives. Zero when logall and logall_json are disabled.", "analysisd"),
    rate("Analysisd: Firewall events written per second", "wazuh.analysisd.firewall.written.rate", "$.analysisd.events.written_breakdown.firewall", "Events written to the firewall log.", "analysisd"),
    rate("Analysisd: Bytes received per second", "wazuh.analysisd.bytes.received.rate", "$.analysisd.bytes.received", "Bytes received by wazuh-analysisd.", "analysisd", "Bps"),

    // remoted
    dep("Remoted: Uptime", "wazuh.remoted.uptime", "$.remoted.uptime", "Time since wazuh-remoted started.", "remoted", { units: "uptime" }),
    dep("Remoted: TCP sessions", "wazuh.remoted.tcp_sessions", "$.remoted.tcp_sessions", "Open TCP sessions with agents.", "remoted"),
    rate("Remoted: Bytes received per second", "wazuh.remoted.bytes.received.rate", "$.remoted.bytes.received", "Bytes received from agents.", "remoted", "Bps"),
    rate("Remoted: Bytes sent per second", "wazuh.remoted.bytes.sent.rate", "$.remoted.bytes.sent", "Bytes sent to agents.", "remoted", "Bps"),
    rate("Remoted: Event messages per second", "wazuh.remoted.messages.event.rate", "$.remoted.messages.received_breakdown.event", "Event messages received from agents.", "remoted", "mps"),
    rate("Remoted: Control messages per second", "wazuh.remoted.messages.control.rate", "$.remoted.messages.received_breakdown.control", "Control messages (keep-alive, startup, shutdown, request) received from agents.", "remoted", "mps"),
    rate("Remoted: Discarded messages per second", "wazuh.remoted.messages.discarded.rate", "$.remoted.messages.received_breakdown.discarded", "Messages from agents discarded by wazuh-remoted.", "remoted", "mps"),
    dep("Remoted: Receive queue size", "wazuh.remoted.queue.size", "$.remoted.queues.received.size", "Capacity of the remoted receive queue, in messages.", "remoted", {
      preprocessing: [heartbeat("1d")],
    }),
    dep("Remoted: Receive queue usage", "wazuh.remoted.queue.usage", "$.remoted.queues.received.usage", "Messages waiting in the remoted receive queue.", "remoted"),
    dep("Remoted: Receive queue utilization", "wazuh.remoted.queue.util", "$.remoted.queues.received.pct", "Utilization of the remoted receive queue.", "remoted", {
      value_type: "FLOAT",
      units: "%",
    }),

    // wazuh-db
    rate("Wazuh DB: Queries per second", "wazuh.db.queries.rate", "$.db.queries.received", "Queries received by wazuh-db.", "wazuh-db", "qps"),
  ],
  rules: [
    {
      name: "Cluster-wide metrics discovery",
      key: "wazuh.cluster.scope.discovery",
      type: "DEPENDENT",
      master: MASTER,
      description: "Creates the agent summary and update items on the master node or on a standalone manager. Nothing is discovered on a worker node.",
      preprocessing: [
        js(`${lldGuard}
return JSON.stringify((data.cluster && data.cluster.role !== 'worker') ? [{'{#SINGLETON}': ''}] : []);`, ["DISCARD_VALUE"]),
        heartbeat("1h"),
      ],
      items: [
        ...(
          [
            ["active", "Active", "Agents connected to the manager."],
            ["disconnected", "Disconnected", "Agents that were connected and lost the connection."],
            ["never_connected", "Never connected", "Registered agents that never connected."],
            ["pending", "Pending", "Agents waiting for the connection to complete."],
            ["total", "Total", "Registered agents."],
          ] as const
        ).map(([f, n, d]): ItemDef => ({
          ...proto,
          name: `Agents: ${n}`,
          key: `wazuh.agents.${f}[{#SINGLETON}]`,
          description: d,
          preprocessing: [jsonpath(`$.agents.${f}`)],
          tags: [["component", "agents"]],
        })),
        {
          ...proto,
          name: "Agents: Disconnected, in %",
          key: "wazuh.agents.disconnected.pct[{#SINGLETON}]",
          value_type: "FLOAT",
          units: "%",
          description: "Share of disconnected agents in all registered agents.",
          preprocessing: [jsonpath("$.agents.disconnected_pct")],
          tags: [["component", "agents"]],
        },
        {
          ...proto,
          name: "Agents: Configuration not synchronized",
          key: "wazuh.agents.not_synced[{#SINGLETON}]",
          description: "Agents whose group configuration is not synchronized.",
          preprocessing: [jsonpath("$.agents.not_synced")],
          tags: [["component", "agents"]],
        },
        {
          ...proto,
          name: "Cluster: Nodes",
          key: "wazuh.cluster.nodes[{#SINGLETON}]",
          description: "Nodes reported by the cluster health check. Zero on a standalone manager.",
          preprocessing: [js("var data = JSON.parse(value);\n\nreturn (data.nodes || []).length;")],
          tags: [["component", "cluster"]],
        },
        {
          ...proto,
          name: "Latest available version",
          key: "wazuh.update.latest[{#SINGLETON}]",
          value_type: "CHAR",
          description:
            "Newest Wazuh release newer than the installed version, as reported by GET /manager/version/check (major, then minor, then patch). Empty when the installation is up to date or the update check is disabled.",
          preprocessing: [jsonpath("$.updates.latest"), heartbeat("1d")],
          tags: [["component", "application"]],
        },
      ],
      graphs: [
        {
          name: "Wazuh: Agents by connection status",
          items: [
            { key: "wazuh.agents.active[{#SINGLETON}]", color: COLOR.green },
            { key: "wazuh.agents.disconnected[{#SINGLETON}]", color: COLOR.red },
            { key: "wazuh.agents.pending[{#SINGLETON}]", color: COLOR.yellow },
            { key: "wazuh.agents.never_connected[{#SINGLETON}]", color: COLOR.grey },
          ],
        },
      ],
    },
    {
      name: "Cluster nodes discovery",
      key: "wazuh.cluster.node.discovery",
      type: "DEPENDENT",
      master: MASTER,
      description: "Discovers cluster nodes from GET /cluster/healthcheck on the master node.",
      preprocessing: [
        js(`${lldGuard}
if (!Array.isArray(data.nodes)) {
	throw 'No cluster node data.';
}

return JSON.stringify(data.nodes.map(function (node) {
	return {'{#NODE.NAME}': node.name, '{#NODE.TYPE}': node.type};
}));`, ["DISCARD_VALUE"]),
        heartbeat("1h"),
      ],
      overrides: [
        {
          name: "Master node",
          macro: "{#NODE.TYPE}",
          value: "^master$",
          ops: [
            { object: "ITEM_PROTOTYPE", like: "keep-alive" },
            { object: "TRIGGER_PROTOTYPE", like: "keep-alive" },
            { object: "TRIGGER_PROTOTYPE", like: "not reported" },
          ],
        },
      ],
      items: [
        {
          name: "Node [{#NODE.NAME}]: Active agents",
          key: "wazuh.cluster.node.agents[{#NODE.NAME}]",
          type: "DEPENDENT",
          master: MASTER,
          description: "Agents connected to the node.",
          preprocessing: [jsonpath("$.nodes[?(@.name=='{#NODE.NAME}')].active_agents.first()")],
          tags: [["component", "cluster"], ["node", "{#NODE.NAME}"]],
        },
        {
          name: "Node [{#NODE.NAME}]: Version",
          key: "wazuh.cluster.node.version[{#NODE.NAME}]",
          type: "DEPENDENT",
          master: MASTER,
          value_type: "CHAR",
          description: "Wazuh version of the node.",
          preprocessing: [jsonpath("$.nodes[?(@.name=='{#NODE.NAME}')].version.first()"), heartbeat("1d")],
          tags: [["component", "cluster"], ["node", "{#NODE.NAME}"]],
        },
        {
          name: "Node [{#NODE.NAME}]: Time since last keep-alive",
          key: "wazuh.cluster.node.keepalive.age[{#NODE.NAME}]",
          type: "DEPENDENT",
          master: MASTER,
          units: "s",
          description: "Time since the master received the last keep-alive from the worker node. Calculated with the clock of the Zabbix server or proxy.",
          preprocessing: [jsonpath("$.nodes[?(@.name=='{#NODE.NAME}')].keepalive_age.first()")],
          tags: [["component", "cluster"], ["node", "{#NODE.NAME}"]],
        },
        {
          name: "Node [{#NODE.NAME}]: Ruleset synchronized",
          key: "wazuh.cluster.node.ruleset.synced[{#NODE.NAME}]",
          type: "DEPENDENT",
          master: MASTER,
          valuemap: "Wazuh boolean",
          description: "Whether the node ruleset matches the master (GET /cluster/ruleset/synchronization).",
          preprocessing: [jsonpath("$.nodes[?(@.name=='{#NODE.NAME}')].ruleset_synced.first()", ["DISCARD_VALUE"])],
          tags: [["component", "cluster"], ["node", "{#NODE.NAME}"]],
        },
      ],
    },
    {
      name: "Analysisd queues discovery",
      key: "wazuh.analysisd.queue.discovery",
      type: "DEPENDENT",
      master: MASTER,
      description: "Discovers the input and output queues of wazuh-analysisd.",
      preprocessing: [
        js(`${lldGuard}
if (!data.analysisd || !data.analysisd.queues) {
	throw 'No analysisd queue data.';
}

return JSON.stringify(Object.keys(data.analysisd.queues).map(function (name) {
	return {'{#QUEUE}': name};
}));`, ["DISCARD_VALUE"]),
        heartbeat("1h"),
      ],
      items: [
        {
          name: "Analysisd: Queue [{#QUEUE}] utilization",
          key: "wazuh.analysisd.queue.util[{#QUEUE}]",
          type: "DEPENDENT",
          master: MASTER,
          value_type: "FLOAT",
          units: "%",
          description: "Utilization of the analysisd queue. A full input queue makes analysisd drop events.",
          preprocessing: [jsonpath("$.analysisd.queues['{#QUEUE}'].pct")],
          tags: [["component", "analysisd"], ["queue", "{#QUEUE}"]],
        },
        {
          name: "Analysisd: Queue [{#QUEUE}] size",
          key: "wazuh.analysisd.queue.size[{#QUEUE}]",
          type: "DEPENDENT",
          master: MASTER,
          description: "Capacity of the analysisd queue, in events.",
          preprocessing: [jsonpath("$.analysisd.queues['{#QUEUE}'].size"), heartbeat("1d")],
          tags: [["component", "analysisd"], ["queue", "{#QUEUE}"]],
        },
      ],
    },
    {
      name: "Daemons discovery",
      key: "wazuh.daemon.discovery",
      type: "DEPENDENT",
      master: MASTER,
      description: "Discovers Wazuh daemons from GET /manager/status. wazuh-clusterd is skipped when the cluster is disabled.",
      filter: [
        { macro: "{#DAEMON}", value: "{$WAZUH.LLD.FILTER.DAEMON.MATCHES}" },
        { macro: "{#DAEMON}", value: "{$WAZUH.LLD.FILTER.DAEMON.NOT_MATCHES}", operator: "NOT_MATCHES_REGEX" },
      ],
      preprocessing: [
        js(`${lldGuard}
if (!data.daemons) {
	throw 'No daemon data.';
}

return JSON.stringify(Object.keys(data.daemons).filter(function (name) {
	return !(name === 'wazuh-clusterd' && data.cluster && data.cluster.enabled === 0);
}).map(function (name) {
	return {'{#DAEMON}': name};
}));`, ["DISCARD_VALUE"]),
        heartbeat("1h"),
      ],
      overrides: [
        {
          name: "Optional daemons",
          macro: "{#DAEMON}",
          value: "{$WAZUH.DAEMON.OPTIONAL.MATCHES}",
          ops: [{ object: "TRIGGER_PROTOTYPE", like: "is not running" }],
        },
      ],
      items: [
        {
          name: "Daemon [{#DAEMON}]: State",
          key: "wazuh.daemon.state[{#DAEMON}]",
          type: "DEPENDENT",
          master: MASTER,
          valuemap: "Wazuh daemon state",
          description: "State of the daemon reported by GET /manager/status.",
          preprocessing: [jsonpath("$.daemons['{#DAEMON}']"), heartbeat("1h")],
          tags: [["component", "daemon"], ["daemon", "{#DAEMON}"]],
        },
      ],
    },
  ],
  triggers: [
    {
      name: "Wazuh: API is not available",
      expression: `max(/${T}/wazuh.api.available,3m)=0`,
      priority: "AVERAGE",
      description: "Login to the Wazuh server API failed for 3 minutes. Check the \"API errors\" item, wazuh-apid on the node, the network path and the API credentials.",
      scope: "availability",
    },
    {
      name: "Wazuh: Failed to fetch API data",
      event_name: "Wazuh: Failed to fetch API data (or no data for 30m)",
      expression: `nodata(/${T}/wazuh.api.available,30m)=1`,
      priority: "WARNING",
      manual_close: true,
      description: "The script item returned no data for 30 minutes. Check the item error and the Zabbix server or proxy log.",
      scope: "availability",
    },
    {
      name: "Wazuh: API requests returned errors",
      expression: `length(last(/${T}/wazuh.api.errors))>0`,
      opdata: "{ITEM.LASTVALUE1}",
      priority: "INFO",
      description: "One or more API requests failed. The items fed by that request have no new data. A common cause is a missing RBAC permission of the monitoring user.",
      depends: ["Wazuh: API is not available"],
      scope: "notice",
    },
    {
      name: "Wazuh: Version has changed",
      expression: `last(/${T}/wazuh.manager.version,#1)<>last(/${T}/wazuh.manager.version,#2) and length(last(/${T}/wazuh.manager.version))>0`,
      priority: "INFO",
      manual_close: true,
      description: "The Wazuh manager version has changed. Acknowledge to close the problem manually.",
      scope: "notice",
    },
    {
      name: "Wazuh: Configuration is not valid",
      expression: `last(/${T}/wazuh.manager.config.valid)=0`,
      priority: "AVERAGE",
      description: "GET /manager/configuration/validation reports an error. The manager will fail to start with the current ossec.conf. Run /var/ossec/bin/wazuh-analysisd -t on the node.",
      scope: "notice",
    },
    {
      name: "Wazuh: Cluster is enabled but not running",
      expression: `last(/${T}/wazuh.cluster.enabled)=1 and last(/${T}/wazuh.cluster.running)=0`,
      priority: "HIGH",
      description: "The cluster is enabled in ossec.conf but wazuh-clusterd is not running. The node does not synchronize with the cluster.",
      scope: "availability",
    },
    {
      name: "Wazuh: Analysisd has been restarted",
      event_name: "Wazuh: Analysisd has been restarted (uptime < 10m)",
      expression: `last(/${T}/wazuh.analysisd.uptime)<10m`,
      priority: "INFO",
      manual_close: true,
      description: "wazuh-analysisd started less than 10 minutes ago.",
      scope: "notice",
    },
    {
      name: "Wazuh: Remoted has been restarted",
      event_name: "Wazuh: Remoted has been restarted (uptime < 10m)",
      expression: `last(/${T}/wazuh.remoted.uptime)<10m`,
      priority: "INFO",
      manual_close: true,
      description: "wazuh-remoted started less than 10 minutes ago.",
      scope: "notice",
    },
    {
      name: "Wazuh: Analysisd is dropping events",
      expression: `min(/${T}/wazuh.analysisd.events.dropped.rate,5m)>0`,
      opdata: "Dropped: {ITEM.LASTVALUE1}",
      priority: "WARNING",
      description: "wazuh-analysisd dropped events for 5 minutes because input queues were full. Events that are dropped do not generate alerts. Check the analysisd queue utilization and the event rate.",
      scope: "performance",
    },
    {
      name: "Wazuh: Remoted receive queue utilization is high",
      event_name: "Wazuh: Remoted receive queue utilization is high (over {$WAZUH.QUEUE.UTIL.MAX.WARN}% for 5m)",
      expression: `min(/${T}/wazuh.remoted.queue.util,5m)>{$WAZUH.QUEUE.UTIL.MAX.WARN}`,
      opdata: "Utilization: {ITEM.LASTVALUE1}",
      priority: "WARNING",
      description: "Messages from agents wait in the remoted receive queue. When the queue is full, remoted discards messages.",
      depends: ["Wazuh: Remoted receive queue utilization is critical"],
      scope: "performance",
    },
    {
      name: "Wazuh: Remoted receive queue utilization is critical",
      event_name: "Wazuh: Remoted receive queue utilization is critical (over {$WAZUH.QUEUE.UTIL.MAX.CRIT}% for 5m)",
      expression: `min(/${T}/wazuh.remoted.queue.util,5m)>{$WAZUH.QUEUE.UTIL.MAX.CRIT}`,
      opdata: "Utilization: {ITEM.LASTVALUE1}",
      priority: "HIGH",
      description: "The remoted receive queue is almost full. Remoted discards messages from agents when the queue is full.",
      scope: "performance",
    },
    // Prototypes
    {
      name: "Wazuh: Too many disconnected agents",
      event_name: "Wazuh: Too many disconnected agents (over {$WAZUH.AGENTS.DISCONNECTED.MAX.WARN}% for 5m)",
      expression: `min(/${T}/wazuh.agents.disconnected.pct[{#SINGLETON}],5m)>{$WAZUH.AGENTS.DISCONNECTED.MAX.WARN}`,
      opdata: "Disconnected: {ITEM.LASTVALUE1}",
      priority: "WARNING",
      description: "The share of disconnected agents is above the threshold.",
      scope: "availability",
    },
    {
      name: "Wazuh: New version is available",
      expression: `length(last(/${T}/wazuh.update.latest[{#SINGLETON}]))>0`,
      opdata: "Available: {ITEM.LASTVALUE1}",
      priority: "INFO",
      description: "The Wazuh update check reports a newer release. Read the release notes before upgrading.",
      scope: "notice",
    },
    {
      name: "Wazuh: Cluster node [{#NODE.NAME}]: Version differs from the master",
      expression: `last(/${T}/wazuh.cluster.node.version[{#NODE.NAME}])<>last(/${T}/wazuh.manager.version)`,
      opdata: "Node: {ITEM.LASTVALUE1}, master: {ITEM.LASTVALUE2}",
      priority: "WARNING",
      description: "All cluster nodes must run the same Wazuh version.",
      scope: "notice",
    },
    {
      name: "Wazuh: Cluster node [{#NODE.NAME}]: No keep-alive from the worker",
      event_name: "Wazuh: Cluster node [{#NODE.NAME}]: No keep-alive from the worker (over {$WAZUH.CLUSTER.KEEPALIVE.MAX.WARN})",
      expression: `min(/${T}/wazuh.cluster.node.keepalive.age[{#NODE.NAME}],5m)>{$WAZUH.CLUSTER.KEEPALIVE.MAX.WARN}`,
      opdata: "Last keep-alive: {ITEM.LASTVALUE1} ago",
      priority: "AVERAGE",
      description: "The master has not received a keep-alive from the worker node. Check wazuh-clusterd on the worker and the network on port 1516/TCP.",
      scope: "availability",
    },
    {
      name: "Wazuh: Cluster node [{#NODE.NAME}]: Node is not reported by the master",
      expression: `nodata(/${T}/wazuh.cluster.node.keepalive.age[{#NODE.NAME}],10m)=1`,
      priority: "AVERAGE",
      description: "The worker node is missing from GET /cluster/healthcheck for 10 minutes. The node is disconnected from the cluster or was removed.",
      depends: ["Wazuh: API is not available"],
      scope: "availability",
    },
    {
      name: "Wazuh: Cluster node [{#NODE.NAME}]: Ruleset is not synchronized",
      expression: `max(/${T}/wazuh.cluster.node.ruleset.synced[{#NODE.NAME}],15m)=0`,
      priority: "WARNING",
      description: "The node ruleset differs from the master for 15 minutes. The node may evaluate events with outdated rules or decoders.",
      scope: "notice",
    },
    {
      name: "Wazuh: Analysisd queue [{#QUEUE}] utilization is high",
      event_name: "Wazuh: Analysisd queue [{#QUEUE}] utilization is high (over {$WAZUH.QUEUE.UTIL.MAX.WARN}% for 5m)",
      expression: `min(/${T}/wazuh.analysisd.queue.util[{#QUEUE}],5m)>{$WAZUH.QUEUE.UTIL.MAX.WARN}`,
      opdata: "Utilization: {ITEM.LASTVALUE1}",
      priority: "WARNING",
      description: "Events wait in the analysisd queue. A full input queue makes analysisd drop events.",
      depends: ["Wazuh: Analysisd queue [{#QUEUE}] utilization is critical"],
      scope: "performance",
    },
    {
      name: "Wazuh: Analysisd queue [{#QUEUE}] utilization is critical",
      event_name: "Wazuh: Analysisd queue [{#QUEUE}] utilization is critical (over {$WAZUH.QUEUE.UTIL.MAX.CRIT}% for 5m)",
      expression: `min(/${T}/wazuh.analysisd.queue.util[{#QUEUE}],5m)>{$WAZUH.QUEUE.UTIL.MAX.CRIT}`,
      opdata: "Utilization: {ITEM.LASTVALUE1}",
      priority: "HIGH",
      description: "The analysisd queue is almost full.",
      scope: "performance",
    },
    {
      name: "Wazuh: Daemon [{#DAEMON}] is not running",
      expression: `last(/${T}/wazuh.daemon.state[{#DAEMON}])<>1`,
      opdata: "State: {ITEM.LASTVALUE1}",
      priority: "AVERAGE",
      description: "The daemon is not running. Daemons that are optional by configuration are matched by {$WAZUH.DAEMON.OPTIONAL.MATCHES} and have no trigger.",
      depends: ["Wazuh: API is not available"],
      scope: "availability",
    },
  ],
  graphs: [
    {
      name: "Wazuh: Analysisd events",
      items: [
        { key: "wazuh.analysisd.events.received.rate", color: COLOR.blue },
        { key: "wazuh.analysisd.events.processed.rate", color: COLOR.green },
        { key: "wazuh.analysisd.events.dropped.rate", color: COLOR.red },
      ],
    },
    {
      name: "Wazuh: Analysisd output",
      items: [
        { key: "wazuh.analysisd.alerts.written.rate", color: COLOR.orange },
        { key: "wazuh.analysisd.archives.written.rate", color: COLOR.grey },
        { key: "wazuh.analysisd.firewall.written.rate", color: COLOR.blue },
      ],
    },
    {
      name: "Wazuh: Remoted messages",
      items: [
        { key: "wazuh.remoted.messages.event.rate", color: COLOR.blue },
        { key: "wazuh.remoted.messages.control.rate", color: COLOR.green },
        { key: "wazuh.remoted.messages.discarded.rate", color: COLOR.red },
      ],
    },
    {
      name: "Wazuh: Remoted traffic",
      items: [
        { key: "wazuh.remoted.bytes.received.rate", color: COLOR.blue },
        { key: "wazuh.remoted.bytes.sent.rate", color: COLOR.green },
      ],
    },
  ],
  dashboards: [
    {
      name: "Wazuh manager",
      pages: [
        {
          name: "Overview",
          widgets: [
            { type: "graph", x: 0, y: 0, width: 36, height: 5, graph: "Wazuh: Analysisd events" },
            { type: "graph", x: 36, y: 0, width: 36, height: 5, graph: "Wazuh: Analysisd output" },
            { type: "graph", x: 0, y: 5, width: 36, height: 5, graph: "Wazuh: Remoted messages" },
            { type: "graph", x: 36, y: 5, width: 36, height: 5, graph: "Wazuh: Remoted traffic" },
            { type: "graphprototype", x: 0, y: 10, width: 72, height: 5, graph: "Wazuh: Agents by connection status", columns: 1, rows: 1 },
          ],
        },
      ],
    },
  ],
};

