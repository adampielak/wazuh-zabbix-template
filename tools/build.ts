#!/usr/bin/env bun
// Author: Adam "tick" Pielak, https://wazuh.blog
// Builds the Zabbix 7.0 template files and their READMEs into templates/.
// Usage: bun tools/build.ts

import { mkdirSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { agent, agentActive } from "./agent.ts";
import { aio } from "./aio.ts";
import { dashboard } from "./dashboard.ts";
import { indexer } from "./indexer.ts";
import { AUTHOR_NOTE, exportDoc, ZABBIX_VERSION, type ItemDef, type TemplateDef } from "./lib.ts";
import { manager } from "./manager.ts";

const ROOT = join(dirname(import.meta.path), "..", "templates");

interface Bundle {
  dir: string;
  file: string;
  templates: TemplateDef[]; // the first one is documented in the README
}

const bundles: Bundle[] = [
  { dir: "wazuh_manager_http", file: "template_app_wazuh_manager_http.yaml", templates: [manager] },
  { dir: "wazuh_indexer_http", file: "template_app_wazuh_indexer_http.yaml", templates: [indexer] },
  { dir: "wazuh_dashboard_http", file: "template_app_wazuh_dashboard_http.yaml", templates: [dashboard] },
  { dir: "wazuh_agent", file: "template_app_wazuh_agent.yaml", templates: [agent, agentActive] },
  { dir: "wazuh_all_in_one", file: "template_app_wazuh_all_in_one.yaml", templates: [aio, manager, indexer, dashboard] },
];

const cell = (s: string) => s.replace(/\|/g, "\\|").replace(/\n+/g, "<br>");

function readme(b: Bundle): string {
  const docs = b.templates.length > 1 && b.dir === "wazuh_agent" ? b.templates : [b.templates[0]];
  const t = b.templates[0];
  const [overview, ...rest] = t.description.split("\n\nSetup:\n\n");
  const setup = rest.join("").split("\n\n");
  const out: string[] = [];

  out.push(`# ${docs.map((d) => d.name).join(" / ")}`, "");
  out.push("## Overview", "", overview, "");
  out.push("## Requirements", "", `Zabbix version: ${ZABBIX_VERSION} and higher.`, "");
  out.push("## Setup", "", ...setup.flatMap((p) => [p, ""]));

  if (t.linked?.length) {
    out.push("## Linked templates", "", "|Name|", "|----|", ...t.linked.map((n) => `|${n}|`), "");
  }

  const macros = t.macros ?? [];
  if (macros.length) {
    out.push("### Macros used", "", "|Name|Description|Default|", "|----|-----------|-------|");
    for (const m of macros) out.push(`|${m.macro}|${cell(m.description)}|${m.secret ? "" : cell(m.value ?? "")}|`);
    out.push("");
  }

  const itemRows = (items: ItemDef[]) =>
    items.map((i) => `|${cell(i.name)}|${cell(i.description)}|${i.type ?? "Zabbix agent"}|${cell(i.key)}|`);

  if (t.items?.length) {
    out.push("### Items", "", "|Name|Description|Type|Key and additional info|", "|----|-----------|----|-----------------------|");
    out.push(...itemRows(t.items), "");
  }

  const protoKeys = new Set((t.rules ?? []).flatMap((r) => r.items.map((i) => i.key)));
  const isProto = (expr: string) => [...protoKeys].some((k) => expr.includes(`/${k}`));
  const plain = (t.triggers ?? []).filter((tr) => !isProto(tr.expression));
  if (plain.length) {
    out.push("### Triggers", "", "|Name|Description|Priority|", "|----|-----------|--------|");
    for (const tr of plain) out.push(`|${cell(tr.name)}|${cell(tr.description)}|${tr.priority}|`);
    out.push("");
  }

  for (const r of t.rules ?? []) {
    out.push(`### LLD rule ${r.name}`, "", cell(r.description), "");
    out.push(`#### Item prototypes for ${r.name}`, "", "|Name|Description|Type|Key and additional info|", "|----|-----------|----|-----------------------|");
    out.push(...itemRows(r.items), "");
    const keys = new Set(r.items.map((i) => i.key));
    const trs = (t.triggers ?? []).filter((tr) => [...keys].some((k) => tr.expression.includes(`/${k}`)));
    if (trs.length) {
      out.push(`#### Trigger prototypes for ${r.name}`, "", "|Name|Description|Priority|", "|----|-----------|--------|");
      for (const tr of trs) out.push(`|${cell(tr.name)}|${cell(tr.description)}|${tr.priority}|`);
      out.push("");
    }
  }

  if (docs.length > 1) {
    out.push(`The template "${docs[1].name}" has the same items and triggers, collected as Zabbix agent (active) checks.`, "");
  }

  out.push("## Author", "", AUTHOR_NOTE.replace("https://wazuh.blog", "[wazuh.blog](https://wazuh.blog)") + ".", "");
  return out.join("\n").replace(/\n{3,}/g, "\n\n");
}

for (const b of bundles) {
  const dir = join(ROOT, b.dir);
  mkdirSync(dir, { recursive: true });
  writeFileSync(join(dir, b.file), exportDoc(b.templates));
  writeFileSync(join(dir, "README.md"), readme(b));
  console.log(`${b.dir}/${b.file}`);
}
