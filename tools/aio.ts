// Author: Adam "tick" Pielak, https://wazuh.blog
// Wazuh all-in-one: links the server, indexer and dashboard templates for a
// single-node deployment (all central components on one host).

import type { TemplateDef } from "./lib.ts";
import { DASHBOARD } from "./dashboard.ts";
import { INDEXER } from "./indexer.ts";
import { MANAGER } from "./manager.ts";

export const AIO = "Wazuh all-in-one";

export const aio: TemplateDef = {
  name: AIO,
  target: "wazuh",
  linked: [MANAGER, INDEXER, DASHBOARD],
  description: `Monitors a Wazuh all-in-one deployment, where the Wazuh server, indexer and dashboard run on one host. Links the templates "${MANAGER}", "${INDEXER}" and "${DASHBOARD}".

Setup:

1. Import this file. It contains the three linked templates.
2. Link the template to the host and set {$WAZUH.API.HOST}, {$WAZUH.INDEXER.HOST} and {$WAZUH.DASHBOARD.HOST} to the address of the Wazuh host.
3. Set the credentials: {$WAZUH.API.USER} and {$WAZUH.API.PASSWORD} for the server API, {$WAZUH.INDEXER.USER} and {$WAZUH.INDEXER.PASSWORD} for the indexer, {$WAZUH.DASHBOARD.USER} and {$WAZUH.DASHBOARD.PASSWORD} for the dashboard status API.

See the descriptions of the linked templates for the required permissions. To monitor the Wazuh agents, link "Wazuh agent by Zabbix agent" or "Wazuh agent by Zabbix agent active" to the agent hosts.

Tested with Wazuh 4.14 and Zabbix 7.0.`,
};
