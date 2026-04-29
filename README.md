# Template Wazuh API by Script (Zabbix 7.x)

Wazuh Zabbix Template
tick@linuxmafia.pl

## Purpose

Template monitors Wazuh via API and covers:

- API health diagnostic (connect/auth/api stages)
- cluster status and node health
- agent status summary
- manager daemon states
- remoted and analysisd queue/events metrics
- node-level LLD (per cluster node)
- 24h SLA calculated metrics

## Authentication flow

The template supports both modes:

1. **Dynamic token (recommended)**
   - Uses `{$WAZUH.USER}` + `{$WAZUH.PASSWORD}`
   - Gets token from `/security/user/authenticate?raw=true`
   - Tries `POST` first, falls back to `GET`
   - Uses `Authorization: Bearer <token>` for API queries

2. **Static token**
   - Set `{$WAZUH.API_TOKEN}`
   - Login step is skipped
   - API calls use provided bearer token directly

## Required macros

- `{$WAZUH.URL}` e.g. `https://127.0.0.1:55000`
- `{$WAZUH.USER}`
- `{$WAZUH.PASSWORD}`
- `{$WAZUH.TIMEOUT}` e.g. `10s`
- `{$WAZUH.API_TOKEN}` optional

## Import

1. Zabbix -> Data collection -> Templates -> Import
2. Import `template-wazuh-7.0.yaml`
3. Link template to your Wazuh API host
4. Set macros on template or host level

## Diagnostic items

- `wazuh.api.diagnostic` (JSON text)
- `wazuh.api.health` (1 = OK, 0 = fail)

Diagnostic `stage` values:

- `ok` -> connectivity/auth/API ok
- `connect` -> cannot connect to server
- `auth` -> cannot obtain token
- `api` -> token obtained but API query failed

## Trigger names with live values

Template includes dynamic values in selected trigger names using `{ITEM.LASTVALUE1}`, for example:

- `Wazuh has {ITEM.LASTVALUE1} disconnected agents`
- `Wazuh has {ITEM.LASTVALUE1} agents with configuration not synced`
- `Wazuh remoted queue usage is high: {ITEM.LASTVALUE1}% (>80%)`
- `Wazuh cluster has {ITEM.LASTVALUE1} unhealthy nodes`

Additional examples included in the template:

- `Wazuh API diagnostic failed (health={ITEM.LASTVALUE1})`
- `Wazuh cluster is not running (running={ITEM.LASTVALUE1})`
- `Wazuh analysisd is not running (running={ITEM.LASTVALUE1})`

## Allow manual close

All regular triggers and trigger prototypes in this template are configured with:

- `manual_close: YES`

This allows operators to close problems manually from the Zabbix UI when needed.

## Main item keys

- `wazuh.snapshot.raw`
- `wazuh.cluster.running`
- `wazuh.agents.disconnected`
- `wazuh.agents.cfg_not_synced`
- `wazuh.remoted.queue.usage`
- `wazuh.analysisd.events.dropped`
- `wazuh.cluster.nodes.discovery`

## Common issue

If you see:

`Cannot execute script: Error: cannot get URL: Couldn't connect to server`

it is network/connectivity, not token parsing.

Check:

- `{$WAZUH.URL}` from Zabbix server perspective
- TCP 55000 reachability
- TLS/certificate chain acceptance
