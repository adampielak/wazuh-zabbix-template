// Author: Adam "tick" Pielak, https://wazuh.blog
// Template model and YAML writer for Zabbix 7.0 export files.
// The output mirrors the layout of the official Zabbix templates
// (https://git.zabbix.com/projects/ZBX/repos/zabbix/browse/templates).

import { createHash } from "node:crypto";

export type Obj = Record<string, unknown>;

export const ZABBIX_VERSION = "7.0";
export const TEMPLATE_GROUP = "Templates/Applications";
// UUID of the "Templates/Applications" group as used by the official templates.
export const TEMPLATE_GROUP_UUID = "a571c0d144b14fd4a87a9d9b2aa9fcd6";
export const VENDOR = { name: "Adam \"tick\" Pielak", version: "7.0-1" };
// Appended to every template description, like the footer of the official templates.
export const AUTHOR_NOTE = "Created by Adam \"tick\" Pielak, https://wazuh.blog";

// Official template guideline colors.
export const COLOR = {
  grey: "97AAB3",
  blue: "7499FF",
  green: "00C48C",
  yellow: "FFBF59",
  orange: "FFA059",
  red: "E45959",
};

// Deterministic UUIDv4: the same template object always gets the same UUID,
// so a rebuild produces a clean diff and a re-import updates objects in place.
export function uuid(...parts: string[]): string {
  const h = createHash("sha256").update(parts.join("\u0000")).digest("hex").slice(0, 32).split("");
  h[12] = "4";
  h[16] = "89ab"[parseInt(h[16], 16) & 3];
  return h.join("");
}

// ---------------------------------------------------------------------------
// YAML writer (block style, single-quoted scalars, literal blocks for text)

const PLAIN = /^[A-Za-z_][A-Za-z0-9_.\-]*$/;
const YAML_WORDS = /^(y|n|yes|no|true|false|on|off|null|~)$/i;

function scalar(s: string): string {
  if (s === "") return "''";
  if (PLAIN.test(s) && !YAML_WORDS.test(s)) return s;
  return "'" + s.replace(/'/g, "''") + "'";
}

function keyName(k: string): string {
  return YAML_WORDS.test(k) ? `'${k}'` : k;
}

function isEmpty(v: unknown): boolean {
  if (v === undefined || v === null) return true;
  if (Array.isArray(v)) return v.length === 0;
  if (typeof v === "object") return Object.keys(v as Obj).length === 0;
  return false;
}

function block(pad: string, s: string, out: string[]) {
  for (const line of s.replace(/\n+$/, "").split("\n")) out.push(line === "" ? "" : pad + line);
}

function emitPair(k: string, v: unknown, ind: number, out: string[]) {
  if (isEmpty(v)) return;
  const pad = " ".repeat(ind);
  if (Array.isArray(v)) {
    out.push(`${pad}${keyName(k)}:`);
    for (const e of v) emitListItem(e, ind + 2, out);
  } else if (typeof v === "object") {
    out.push(`${pad}${keyName(k)}:`);
    emitMap(v as Obj, ind + 2, out);
  } else {
    const s = String(v);
    if (s.includes("\n")) {
      out.push(`${pad}${keyName(k)}: |`);
      block(pad + "  ", s, out);
    } else {
      out.push(`${pad}${keyName(k)}: ${scalar(s)}`);
    }
  }
}

function emitMap(o: Obj, ind: number, out: string[]) {
  for (const [k, v] of Object.entries(o)) emitPair(k, v, ind, out);
}

function emitListItem(e: unknown, ind: number, out: string[]) {
  const pad = " ".repeat(ind);
  if (e !== null && typeof e === "object" && !Array.isArray(e)) {
    const sub: string[] = [];
    emitMap(e as Obj, ind + 2, sub);
    if (sub.length === 0) return;
    sub[0] = `${pad}- ${sub[0].slice(ind + 2)}`;
    out.push(...sub);
    return;
  }
  const s = String(e);
  if (s.includes("\n")) {
    out.push(`${pad}- |`);
    block(pad + "  ", s, out);
  } else {
    out.push(`${pad}- ${scalar(s)}`);
  }
}

export function toYaml(doc: Obj): string {
  const out: string[] = [];
  emitMap(doc, 0, out);
  return out.join("\n") + "\n";
}

// ---------------------------------------------------------------------------
// Template model

export type Tag = [string, string];
const tags = (t?: Tag[]) => (t ?? []).map(([tag, value]) => ({ tag, value }));

export interface Step {
  type: string;
  parameters?: string[];
  error_handler?: string;
  error_handler_params?: string;
}

export const jsonpath = (p: string, onError?: [string, string?]): Step => ({
  type: "JSONPATH",
  parameters: [p],
  ...(onError ? { error_handler: onError[0], error_handler_params: onError[1] } : {}),
});
export const js = (code: string, onError?: [string, string?]): Step => ({
  type: "JAVASCRIPT",
  parameters: [code],
  ...(onError ? { error_handler: onError[0], error_handler_params: onError[1] } : {}),
});
export const heartbeat = (period: string): Step => ({ type: "DISCARD_UNCHANGED_HEARTBEAT", parameters: [period] });
export const perSecond = (): Step => ({ type: "CHANGE_PER_SECOND", parameters: [""] });
export const multiplier = (m: string): Step => ({ type: "MULTIPLIER", parameters: [m] });
export const regex = (pattern: string, output: string, onError?: [string, string?]): Step => ({
  type: "REGEX",
  parameters: [pattern, output],
  ...(onError ? { error_handler: onError[0], error_handler_params: onError[1] } : {}),
});

export interface ItemDef {
  name: string;
  key: string;
  type?: string; // omitted = ZABBIX_PASSIVE
  delay?: string;
  history?: string;
  value_type?: "FLOAT" | "CHAR" | "LOG" | "TEXT" | "UNSIGNED";
  trends?: string;
  units?: string;
  description: string;
  valuemap?: string;
  preprocessing?: Step[];
  master?: string;
  tags: Tag[];
  extra?: Obj; // type specific fields (url, params, parameters, timeout, ...)
}

export interface TriggerDef {
  name: string;
  expression: string;
  event_name?: string;
  opdata?: string;
  priority: "INFO" | "WARNING" | "AVERAGE" | "HIGH";
  description: string;
  manual_close?: boolean;
  recovery_expression?: string;
  depends?: string[]; // names of other triggers in the same template
  scope: "availability" | "performance" | "capacity" | "notice" | "security";
}

export interface GraphDef {
  name: string;
  items: { key: string; color: string; drawtype?: string; yaxisside?: string }[];
  ymin0?: boolean;
}

export interface OverrideDef {
  name: string;
  macro: string;
  value: string;
  operator?: "MATCHES_REGEX" | "NOT_MATCHES_REGEX";
  ops: { object: "ITEM_PROTOTYPE" | "TRIGGER_PROTOTYPE" | "GRAPH_PROTOTYPE"; like: string }[];
}

export interface RuleDef {
  name: string;
  key: string;
  type?: string;
  delay?: string;
  description: string;
  master?: string;
  preprocessing?: Step[];
  filter?: { macro: string; value: string; operator?: "NOT_MATCHES_REGEX" }[];
  overrides?: OverrideDef[];
  lifetime?: string;
  extra?: Obj;
  items: ItemDef[];
  graphs?: GraphDef[];
}

export interface MacroDef {
  macro: string;
  value?: string;
  secret?: boolean;
  description: string;
}

export interface ValueMapDef {
  name: string;
  map: [string, string][];
}

export interface Widget {
  type: "graph" | "graphprototype";
  x: number;
  y: number;
  width: number;
  height: number;
  graph: string; // graph or graph prototype name
  columns?: number;
  rows?: number;
}

export interface TemplateDef {
  name: string;
  description: string;
  target: string;
  linked?: string[];
  items?: ItemDef[];
  rules?: RuleDef[];
  triggers?: TriggerDef[];
  graphs?: GraphDef[];
  macros?: MacroDef[];
  valuemaps?: ValueMapDef[];
  dashboards?: { name: string; pages: { name: string; widgets: Widget[] }[] }[];
}

// Extract item keys referenced as /<template>/<key> in a trigger expression.
export function itemRefs(expr: string, template: string): string[] {
  const keys: string[] = [];
  const marker = `/${template}/`;
  let i = 0;
  while ((i = expr.indexOf(marker, i)) !== -1) {
    let j = i + marker.length;
    let depth = 0;
    let inQuote = false;
    for (; j < expr.length; j++) {
      const c = expr[j];
      if (inQuote) {
        if (c === "\\") j++;
        else if (c === '"') inQuote = false;
        continue;
      }
      if (c === '"') inQuote = true;
      else if (c === "[") depth++;
      else if (c === "]") {
        depth--;
        if (depth === 0) {
          j++;
          break;
        }
      } else if (depth === 0 && (c === "," || c === ")")) break;
    }
    keys.push(expr.slice(i + marker.length, j));
    i = j;
  }
  return [...new Set(keys)];
}

export function buildTemplate(t: TemplateDef): Obj {
  const u = (...p: string[]) => uuid(t.name, ...p);
  const itemObjs = new Map<string, Obj>();
  const protoObjs = new Map<string, { item: Obj; rule: Obj }>();

  const item = (d: ItemDef, prototype: boolean): Obj => {
    const o: Obj = {
      uuid: u(prototype ? "item_prototype" : "item", d.key),
      name: d.name,
      type: d.type,
      key: d.key,
      delay: d.type === "DEPENDENT" ? "0" : d.delay,
      history: d.history,
      value_type: d.value_type,
      trends: d.value_type === "TEXT" || d.value_type === "CHAR" ? "0" : d.trends,
      units: d.units,
      ...d.extra,
      description: d.description,
      valuemap: d.valuemap ? { name: d.valuemap } : undefined,
      preprocessing: d.preprocessing,
      master_item: d.master ? { key: d.master } : undefined,
      tags: tags(d.tags),
    };
    return o;
  };

  const items = (t.items ?? []).map((d) => {
    const o = item(d, false);
    itemObjs.set(d.key, o);
    return o;
  });

  const graph = (g: GraphDef, prototype: boolean): Obj => ({
    uuid: u(prototype ? "graph_prototype" : "graph", g.name),
    name: g.name,
    ymin_type_1: g.ymin0 === false ? undefined : "FIXED",
    graph_items: g.items.map((gi, n) => ({
      sortorder: n === 0 ? undefined : String(n),
      drawtype: gi.drawtype,
      color: gi.color,
      yaxisside: gi.yaxisside,
      item: { host: t.name, key: gi.key },
    })),
  });

  const rules = (t.rules ?? []).map((r) => {
    const ro: Obj = {
      uuid: u("discovery_rule", r.key),
      name: r.name,
      type: r.type,
      key: r.key,
      delay: r.type === "DEPENDENT" ? "0" : r.delay,
      lifetime: r.lifetime,
      ...r.extra,
      filter: r.filter
        ? {
            evaltype: "AND",
            conditions: r.filter.map((c, n) => ({
              macro: c.macro,
              value: c.value,
              operator: c.operator,
              formulaid: String.fromCharCode(65 + n),
            })),
          }
        : undefined,
      description: r.description,
      item_prototypes: [] as Obj[],
      trigger_prototypes: [] as Obj[],
      graph_prototypes: (r.graphs ?? []).map((g) => graph(g, true)),
      master_item: r.master ? { key: r.master } : undefined,
      preprocessing: r.preprocessing,
      overrides: (r.overrides ?? []).map((ov, n) => ({
        name: ov.name,
        step: String(n + 1),
        filter: {
          conditions: [{ macro: ov.macro, value: ov.value, operator: ov.operator, formulaid: "A" }],
        },
        operations: ov.ops.map((op) => ({
          operationobject: op.object,
          operator: "LIKE",
          value: op.like,
          discover: "NO_DISCOVER",
        })),
      })),
    };
    for (const d of r.items) {
      const o = item(d, true);
      (ro.item_prototypes as Obj[]).push(o);
      protoObjs.set(d.key, { item: o, rule: ro });
    }
    return ro;
  });

  // Triggers: single-item triggers live under their item, the rest at the top level
  // (or under the discovery rule for prototypes), as in Zabbix exports.
  const topTriggers: Obj[] = [];
  const byName = new Map<string, TriggerDef>();
  for (const tr of t.triggers ?? []) byName.set(tr.name, tr);
  for (const tr of t.triggers ?? []) {
    const refs = itemRefs(`${tr.expression} ${tr.recovery_expression ?? ""}`, t.name);
    if (refs.length === 0) throw new Error(`${t.name}: trigger "${tr.name}" references no item`);
    for (const k of refs) {
      if (!itemObjs.has(k) && !protoObjs.has(k)) throw new Error(`${t.name}: trigger "${tr.name}" references unknown key ${k}`);
    }
    const proto = refs.some((k) => protoObjs.has(k));
    const o: Obj = {
      uuid: u(proto ? "trigger_prototype" : "trigger", tr.name),
      expression: tr.expression,
      recovery_mode: tr.recovery_expression ? "RECOVERY_EXPRESSION" : undefined,
      recovery_expression: tr.recovery_expression,
      name: tr.name,
      event_name: tr.event_name,
      opdata: tr.opdata,
      priority: tr.priority,
      description: tr.description,
      manual_close: tr.manual_close ? "YES" : undefined,
      dependencies: (tr.depends ?? []).map((n) => {
        const dep = byName.get(n);
        if (!dep) throw new Error(`${t.name}: unknown dependency "${n}" in "${tr.name}"`);
        return { name: dep.name, expression: dep.expression, recovery_expression: dep.recovery_expression };
      }),
      tags: tags([["scope", tr.scope]]),
    };
    if (refs.length === 1 && proto) {
      const p = protoObjs.get(refs[0])!;
      ((p.item.trigger_prototypes as Obj[]) ??= []).push(o);
    } else if (refs.length === 1) {
      const it = itemObjs.get(refs[0])!;
      ((it.triggers as Obj[]) ??= []).push(o);
    } else if (proto) {
      const rule = protoObjs.get(refs.find((k) => protoObjs.has(k))!)!.rule;
      (rule.trigger_prototypes as Obj[]).push(o);
    } else {
      topTriggers.push(o);
    }
  }

  let ref = 0;
  const reference = () => {
    let n = ref++;
    let s = "";
    for (let i = 0; i < 5; i++) {
      s = String.fromCharCode(65 + (n % 26)) + s;
      n = Math.floor(n / 26);
    }
    return s;
  };

  const template: Obj = {
    uuid: u("template"),
    template: t.name,
    name: t.name,
    description: `${t.description}\n\n${AUTHOR_NOTE}`,
    vendor: VENDOR,
    templates: (t.linked ?? []).map((name) => ({ name })),
    groups: [{ name: TEMPLATE_GROUP }],
    items,
    discovery_rules: rules,
    tags: tags([
      ["class", "software"],
      ["target", t.target],
    ]),
    macros: [...(t.macros ?? [])]
      .sort((a, b) => a.macro.localeCompare(b.macro))
      .map((m) => ({
        macro: m.macro,
        type: m.secret ? "SECRET_TEXT" : undefined,
        value: m.value,
        description: m.description,
      })),
    dashboards: (t.dashboards ?? []).map((d) => ({
      uuid: u("dashboard", d.name),
      name: d.name,
      pages: d.pages.map((p) => ({
        name: p.name,
        widgets: p.widgets.map((w) => ({
          type: w.type,
          x: w.x ? String(w.x) : undefined,
          y: w.y ? String(w.y) : undefined,
          width: String(w.width),
          height: String(w.height),
          fields: [
            {
              type: w.type === "graph" ? "GRAPH" : "GRAPH_PROTOTYPE",
              name: "graphid.0",
              value: { host: t.name, name: w.graph },
            },
            ...(w.columns ? [{ type: "INTEGER", name: "columns", value: String(w.columns) }] : []),
            ...(w.rows ? [{ type: "INTEGER", name: "rows", value: String(w.rows) }] : []),
            { type: "STRING", name: "reference", value: reference() },
          ],
        })),
      })),
    })),
    valuemaps: (t.valuemaps ?? []).map((v) => ({
      uuid: u("valuemap", v.name),
      name: v.name,
      mappings: v.map.map(([value, newvalue]) => ({ value, newvalue })),
    })),
  };

  return {
    template,
    triggers: topTriggers,
    graphs: (t.graphs ?? []).map((g) => graph(g, false)),
  };
}

export function exportDoc(defs: TemplateDef[]): string {
  const built = defs.map(buildTemplate);
  return toYaml({
    zabbix_export: {
      version: ZABBIX_VERSION,
      template_groups: [{ uuid: TEMPLATE_GROUP_UUID, name: TEMPLATE_GROUP }],
      templates: built.map((b) => b.template),
      triggers: built.flatMap((b) => b.triggers as Obj[]),
      graphs: built.flatMap((b) => b.graphs as Obj[]),
    },
  });
}
