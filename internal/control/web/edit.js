// The views that change the run's rules: the chaos switch, the scenario
// builder, removing and saving the live rules, the rules queued for the
// next reset, and the scenarios. Each change says whether it applies now or
// at the next reset.

import { APIError, get, runPath, send } from "./api.js";
import { anchors, catalogue, compileRule, triggerLabels } from "./builder.js";
import { chaosOf, chaosScopes, formOf } from "./chaos.js";
import { el, show } from "./dom.js";
import { describeAction, describeChaos, describeMatch } from "./rules.js";

const $ = (id) => document.getElementById(id);

// liveWarning is what applying a change during a run means for transfers
// already under way.
const liveWarning =
  "This changes the current run's rules now. Transfers already open keep the faults chosen for them when they opened; new requests and transfers get the new rules.";

let ctx;

// setup wires the views to ctx: run(), the current run's ID, showError(err),
// and changed(), which the page calls after a change, to show the rules and
// status again.
export function setup(context) {
  ctx = context;
  setupChaos();
  setupBuilder();
  $("save-live").addEventListener("click", saveLive);
  $("save-form").addEventListener("submit", submitSave);
  $("save-cancel").addEventListener("click", () => $("save-dialog").close());
}

// changeLive replaces the current run's rules and chaos with what change,
// given the current rules reply, returns, after the user confirms.
async function changeLive(change) {
  const run = ctx.run();
  const current = await get(runPath(run, "rules"));
  const next = change(current);
  if (!confirm(liveWarning)) {
    return false;
  }
  await send("PUT", runPath(run, "rules"), { revision: current.revision, faults: next.faults, chaos: next.chaos ?? null });
  ctx.changed();
  return true;
}

// --- Chaos ---

function setupChaos() {
  const form = $("chaos-form");
  show(form.elements.scope, Object.entries(chaosScopes).map(([value, label]) => el("option", { value }, label)));
  form.addEventListener("submit", async (ev) => {
    ev.preventDefault();
    try {
      const chaos = chaosOf(chaosForm());
      if (await changeLive((current) => ({ faults: current.faults, chaos }))) {
        show($("chaos-note"), chaos ? `Applied now: ${describeChaos(chaos)}.` : "Applied now: chaos is off.");
      }
    } catch (err) {
      show($("chaos-note"), el("span", { class: "error-text" }, err.message));
    }
  });
  $("chaos-preview-button").addEventListener("click", previewChaos);
}

function chaosForm() {
  const f = $("chaos-form").elements;
  return {
    mode: f.mode.value,
    preset: f.preset.value,
    scope: f.scope.value,
    scope_value: f.scope_value.value,
    extras: [...f.extras].filter((x) => x.checked).map((x) => x.value),
  };
}

// loadChaos fills the switch with the current run's chaos.
export async function loadChaos() {
  try {
    const current = await get(runPath(ctx.run(), "rules"));
    const values = formOf(current.chaos);
    const f = $("chaos-form").elements;
    for (const radio of f.mode) {
      radio.checked = radio.value === values.mode;
    }
    f.preset.value = values.preset;
    if (![...f.scope.options].some((o) => o.value === values.scope)) {
      f.scope.append(el("option", { value: values.scope }, values.scope.replaceAll("_", " ")));
    }
    f.scope.value = values.scope;
    f.scope_value.value = values.scope_value;
    for (const box of f.extras) {
      box.checked = values.extras.includes(box.value);
    }
    show($("chaos-note"), `Revision ${current.revision}. ${current.chaos ? `Now: ${describeChaos(current.chaos)}.` : "Chaos is off."} Changes apply now, to the current run.`);
    await previewChaos();
  } catch (err) {
    ctx.showError(err);
  }
}

// previewChaos shows the rules that the switch's chaos compiles to.
async function previewChaos() {
  const box = $("chaos-preview");
  try {
    const chaos = chaosOf(chaosForm());
    if (!chaos) {
      show(box, el("p", { class: "muted" }, "No chaos: only the run's own rules apply."));
      return;
    }
    const checked = await send("POST", "/api/v1/rules/check", { faults: [], chaos });
    show(box, el("h3", {}, "The rules this chaos applies, after the run's own"), rulesTable(checked.compiled_chaos));
  } catch (err) {
    show(box, el("p", { class: "error-text" }, err.message));
  }
}

function rulesTable(rules) {
  return el(
    "div",
    { class: "scroll" },
    el(
      "table",
      { class: "rules" },
      el("thead", {}, el("tr", {}, el("th", { scope: "col" }, "Rule"), el("th", { scope: "col" }, "Matches"), el("th", { scope: "col" }, "Does"))),
      el("tbody", {}, rules.map((r) => el("tr", {}, el("td", {}, el("code", {}, r.id)), el("td", {}, describeMatch(r)), el("td", {}, describeAction(r))))),
    ),
  );
}

// --- The builder ---

// checked is the rule that the last preview checked, which the builder's
// apply buttons apply, or null once the form changes.
let checked = null;

function setupBuilder() {
  const form = $("builder-form");
  const f = form.elements;
  show(f.fault, Object.entries(catalogue).map(([value, fault]) => el("option", { value }, fault.label)));
  form.addEventListener("input", () => {
    checked = null;
    $("builder-apply").disabled = true;
    $("builder-queue").disabled = true;
  });
  form.addEventListener("change", builderFields);
  form.addEventListener("submit", async (ev) => {
    ev.preventDefault();
    await previewRule();
  });
  $("builder-apply").addEventListener("click", applyRule);
  $("builder-queue").addEventListener("click", queueRule);
  builderFields();
}

// builderFields shows the fields of the chosen fault and trigger only.
function builderFields() {
  const f = $("builder-form").elements;
  const fault = catalogue[f.fault.value];
  const trigger = f.trigger.value;
  const triggers = fault.triggers;
  if (f.trigger.options.length !== triggers.length || ![...f.trigger.options].every((o, i) => o.value === triggers[i])) {
    show(f.trigger, triggers.map((t) => el("option", { value: t }, triggerLabels[t])));
    f.trigger.value = triggers.includes(trigger) ? trigger : triggers[0];
  }
  for (const label of document.querySelectorAll("#builder-form [data-setting]")) {
    label.hidden = !fault.settings.includes(label.dataset.setting);
  }
  const result = f.result.value;
  if (f.fault.value.startsWith("partial_")) {
    $("builder-form").querySelector('[data-setting="status"]').hidden = result !== "status";
    $("builder-form").querySelector('[data-setting="mode"]').hidden = result !== "close_connection";
    $("builder-form").querySelector('[data-setting="max_freeze"]').hidden = result !== "freeze_connection";
  }
  for (const label of document.querySelectorAll("#builder-form [data-trigger]")) {
    label.hidden = !label.dataset.trigger.split(" ").includes(f.trigger.value);
  }
  const allowed = anchors[f.trigger.value] ?? [];
  if ([...f.anchor.options].map((o) => o.value).join() !== allowed.join()) {
    const anchor = f.anchor.value;
    show(f.anchor, allowed.map((a) => el("option", { value: a }, `the ${a === "transfer" ? "transfer's open" : a}`)));
    f.anchor.value = allowed.includes(anchor) ? anchor : allowed[0] ?? "";
  }
}

function builderForm() {
  const f = $("builder-form").elements;
  const names = ["id", "fault", "user", "key_fingerprint", "location", "location_value", "operations", "trigger", "attempts", "occurrence", "probability", "at", "from", "until", "anchor",
    "when", "duration", "status", "mode", "max_freeze", "max_stall", "cutoff", "result", "transform", "offset", "length", "size_delta"];
  // namedItem, since a control named length is hidden by the collection's
  // own length.
  const form = Object.fromEntries(names.map((n) => [n, f.namedItem(n).value]));
  // A hidden field is not part of the fault: a partial upload that closes
  // the connection has no status.
  for (const label of document.querySelectorAll("#builder-form [data-setting]")) {
    if (label.hidden) {
      form[label.dataset.setting] = "";
    }
  }
  return form;
}

// previewRule compiles the form and has the server check the rule,
// showing it in the long form, as the engine would run it.
async function previewRule() {
  const box = $("builder-preview");
  checked = null;
  try {
    const rule = compileRule(builderForm());
    const reply = await send("POST", "/api/v1/rules/check", { faults: [rule] });
    checked = rule;
    const long = reply.faults[0];
    show(
      box,
      el("h3", {}, "The rule, as sftpit runs it"),
      el("p", {}, el("code", {}, long.id), `: ${describeMatch(long)}; ${describeAction(long)}.`),
      el("pre", { class: "preview text" }, JSON.stringify(long, null, 2)),
    );
    show($("builder-note"), "Apply it now, to the current run, or at the next reset, to a run that starts with it.");
  } catch (err) {
    show(box, el("p", { class: "error-text" }, err.message));
    show($("builder-note"));
  }
  $("builder-apply").disabled = checked === null;
  $("builder-queue").disabled = checked === null;
}

async function applyRule() {
  const rule = checked;
  try {
    if (await changeLive((current) => ({ faults: [...current.faults, rule], chaos: current.chaos }))) {
      show($("builder-note"), `Applied now: the current run has the rule ${rule.id}.`);
    }
  } catch (err) {
    show($("builder-note"), el("span", { class: "error-text" }, err.message));
  }
}

// queueRule adds the rule to what the next reset starts with: what is
// queued already, or else the current run's rules and chaos.
async function queueRule() {
  const rule = checked;
  try {
    const status = await get("/api/v1/status");
    const base = status.queued ? await get("/api/v1/next") : await get(runPath(ctx.run(), "rules"));
    await send("PUT", "/api/v1/next", { faults: [...base.faults, rule], chaos: base.chaos ?? null });
    show($("builder-note"), `Queued: the next reset that names no scenario starts a run with ${rule.id} and ${count(base.faults.length, "other rule")}. The current run is unchanged.`);
    ctx.changed();
  } catch (err) {
    show($("builder-note"), el("span", { class: "error-text" }, err.message));
  }
}

// --- The live rules ---

// removeRule removes a rule from the current run, after the user confirms.
export async function removeRule(id) {
  try {
    await changeLive((current) => ({ faults: current.faults.filter((r) => r.id !== id), chaos: current.chaos }));
  } catch (err) {
    ctx.showError(err);
  }
}

// queuedKey identifies what the queued section shows.
let queuedKey = null;

// showQueued shows what is queued for the next reset, if anything, and
// shows it again only if it changed, so that its button is never replaced
// under a click on it.
export async function showQueued(queued) {
  const box = $("queued");
  if (!queued) {
    queuedKey = null;
    show(box);
    return;
  }
  try {
    const next = await get("/api/v1/next");
    const key = JSON.stringify(next);
    if (key === queuedKey) {
      return;
    }
    queuedKey = key;
    show(
      box,
      el("h3", {}, "Queued for the next reset"),
      el("p", { class: "muted" }, `The next reset that names no scenario starts a run with ${count(next.faults.length, "rule")}${next.chaos ? ` and ${describeChaos(next.chaos)}` : ""}, in place of repeating the current scenario. Any reset clears the queue.`),
      rulesTable(next.faults),
      el("p", {}, el("button", { type: "button", onclick: unqueue }, "Clear the queue")),
    );
  } catch (err) {
    // Another tab may have cleared it, or a reset taken it, since the status.
    if (!(err instanceof APIError && err.status === 404)) {
      ctx.showError(err);
    }
    queuedKey = null;
    show(box);
  }
}

async function unqueue() {
  try {
    await send("DELETE", "/api/v1/next");
    ctx.changed();
  } catch (err) {
    ctx.showError(err);
  }
}

// --- Saving scenarios ---

// saving is what the save dialog saves: the scenario's rules, chaos and
// seed, or null for the live rules, which it reads as it saves.
let saving = null;

function saveLive() {
  saving = null;
  openSave("Save as scenario", "Saves the current run's rules and chaos, as they are now, and its seed if it is pinned, to a scenario file, which a reset can then start a run with.", "");
}

// duplicate opens the save dialog for a copy of a configured scenario.
function duplicate(s) {
  saving = { faults: s.faults, chaos: s.chaos ?? null, seed: s.seed ?? null, description: s.description ?? "" };
  openSave(`Duplicate ${s.name} to a file`, "The configuration file is never rewritten, so its scenarios are copied to a file to change them.", `${s.name}-copy`, s.description);
}

function openSave(heading, what, name, description = "") {
  const f = $("save-form").elements;
  show($("save-heading"), heading);
  show($("save-what"), what);
  show($("save-error"));
  f.name.value = name;
  f.description.value = description;
  $("save-dialog").showModal();
}

async function submitSave(ev) {
  ev.preventDefault();
  const f = $("save-form").elements;
  const name = f.name.value.trim();
  try {
    const body = saving ? { ...saving } : await liveScenario();
    body.description = f.description.value;
    const { scenarios } = await get("/api/v1/scenarios");
    const existing = scenarios.find((s) => s.name === name && s.source === "file");
    if (existing) {
      if (!confirm(`${existing.path} already holds a scenario ${name}. Replace it?`)) {
        return;
      }
      body.hash = existing.hash;
    }
    const saved = await send("PUT", `/api/v1/scenarios/${encodeURIComponent(name)}`, body);
    $("save-dialog").close();
    show($("rules-saved"), `Saved to ${saved.path}.`);
    loadScenarios();
  } catch (err) {
    show($("save-error"), err.message);
  }
}

// liveScenario returns the current run's rules and chaos as a scenario,
// with the run's seed if it is pinned, so that the scenario repeats the
// run's decisions as well as its rules.
async function liveScenario() {
  const [current, status] = await Promise.all([get(runPath(ctx.run(), "rules")), get("/api/v1/status")]);
  const scenario = { faults: current.faults, chaos: current.chaos ?? null };
  if (status.run.seed_pinned) {
    scenario.seed = status.run.seed;
  }
  return scenario;
}

function count(n, thing) {
  return `${n} ${thing}${n === 1 ? "" : "s"}`;
}

// --- Scenarios ---

// loadScenarios lists the configuration's scenarios and the files.
export async function loadScenarios() {
  try {
    const { dir, scenarios } = await get("/api/v1/scenarios");
    show($("scenarios-note"), dir ? `Scenario files are saved in ${dir}. A reset to one reads its file then, so an edit applies at the next reset.` : "");
    show(
      $("scenario-rows"),
      scenarios.length === 0
        ? el("tr", {}, el("td", { colspan: 5, class: "muted" }, "No scenarios yet: save the live rules, or duplicate one from the configuration."))
        : scenarios.map((s) =>
            el(
              "tr",
              { class: s.error ? "broken" : "" },
              el("td", {}, el("code", {}, s.name)),
              el("td", {}, s.source === "file" ? el("span", { title: `sha256 ${s.hash}` }, s.path) : "configuration, read-only"),
              el("td", {}, s.error ? el("span", { class: "error-text" }, s.error) : s.description ?? ""),
              el("td", {}, s.error ? "" : `${count(s.faults.length, "rule")}${s.chaos ? `, ${describeChaos(s.chaos)}` : ""}${s.seed ? `, seed ${s.seed}` : ""}`),
              el("td", {}, s.source === "config" ? el("button", { type: "button", onclick: () => duplicate(s) }, "Duplicate to file") : ""),
            ),
          ),
    );
  } catch (err) {
    ctx.showError(err);
  }
}
