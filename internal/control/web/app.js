// The dashboard: the faults of the current run, which can be switched on and
// off, what clients did, the server's files, and how to do the same from a
// test. It follows the current run, so after a reset it shows the next.

import { describeLine, describeRequest, isProblem, isRoutine } from "./activity.js";
import { APIError, get, send } from "./api.js";
import { connectCommands } from "./connection.js";
import { el, show } from "./dom.js";
import { describeFault, faultBody, presetSetting, summarise } from "./faults.js";
import { formatBytes, formatClock } from "./format.js";
import { keepNumbers } from "./number.js";
import { treeRows } from "./tree.js";

// pollInterval is how often the page asks what has changed.
const pollInterval = 1000;

const $ = (id) => document.getElementById(id);

const state = {
  server: null,
  catalogue: null,
  view: "faults",
  run: null,
  faultsKey: "",
  lastEvent: null,
  lines: [],
  filter: "all",
  routine: false,
  newestFirst: storedOrder(),
  clearedAfter: 0,
  expanded: new Set(),
  picked: "deletes_fail",
  custom: { steps: new Set(["remove"]), do: "refuse", from: "" },
  polls: 0,
};

// --- Errors ---

function showError(err) {
  const banner = $("error");
  if (err === null) {
    banner.hidden = true;
    return;
  }
  show(banner, err instanceof APIError ? err.message : `sftpit cannot be reached: ${err.message}`);
  banner.hidden = false;
}

// --- Views ---

const views = ["faults", "custom", "files", "test"];

function route() {
  const name = location.hash.slice(1);
  state.view = views.includes(name) ? name : "faults";
  for (const v of views) {
    $(`view-${v}`).hidden = v !== state.view;
  }
  const current = state.view === "custom" ? "faults" : state.view;
  for (const a of document.querySelectorAll(".views a")) {
    if (a.dataset.view === current) {
      a.setAttribute("aria-current", "page");
    } else {
      a.removeAttribute("aria-current");
    }
  }
  if (state.view === "custom") {
    showCustom();
  } else if (state.view === "files") {
    loadFiles();
  }
  window.scrollTo(0, 0);
}

// --- Polling ---

async function poll() {
  try {
    const status = await get("/api/status");
    showStatus(status);
    if (status.run.id !== state.run) {
      state.run = status.run.id;
      state.lastEvent = null;
      state.clearedAfter = 0;
      state.expanded.clear();
      if (state.view === "files") {
        loadFiles();
      }
    }
    await loadFaults();
    if (state.view === "faults") {
      await loadActivity();
    }
    state.polls++;
    if (state.view === "files" && state.polls % 3 === 0) {
      await loadFiles();
    }
    showError(null);
  } catch (err) {
    showError(err);
    showPill("Unreachable", "bad");
  }
}

function showStatus(status) {
  const s = status.sftp;
  const states = {
    up: ["Running", "up"],
    down: ["Down", "down"],
    resetting: ["Starting again", ""],
    draining: ["Pausing", ""],
    drained: ["Paused", ""],
    unavailable: ["Unavailable", "bad"],
  };
  const [text, tone] = states[s.state] ?? [s.state, ""];
  showPill(s.state === "down" && s.down_until ? `Down until ${formatClock(s.down_until)}` : text, tone);
  $("release").hidden = status.run.stalled + status.run.frozen === 0;
}

function showPill(text, tone) {
  const pill = $("state");
  show(pill, text);
  pill.className = `pill ${tone}`;
}

// --- How to connect ---

function showServer(server) {
  const command = connectCommands(server)[0];
  show($("connect-command"), command ? command.command : server.sftp_address);
  const login = server.default_login;
  $("connect-password").hidden = !login;
  if (login) {
    show($("password"), login.password);
  }
  for (const select of document.querySelectorAll('select[name="user"]')) {
    show(select, el("option", { value: "" }, "Any user"), server.users.map((u) => el("option", { value: u.name }, u.name)));
  }
  for (const field of document.querySelectorAll(".user-field")) {
    field.hidden = server.users.length < 2;
  }
}

// --- Faults ---

async function loadFaults() {
  const { faults } = await get("/api/faults");
  const key = JSON.stringify(faults);
  if (key === state.faultsKey) {
    return;
  }
  state.faultsKey = key;
  $("no-faults").hidden = faults.length > 0;
  show($("fault-list"), faults.map(faultCard));
}

function faultCard(f) {
  const d = describeFault(f);
  return el(
    "article",
    { class: f.on ? "fault-card on" : "fault-card" },
    el(
      "div",
      { class: "fault-top" },
      el("div", {}, el("h2", {}, d.name), el("p", {}, d.summary)),
      el(
        "button",
        { type: "button", class: "switch", "aria-pressed": String(f.on), "aria-label": `${f.on ? "Turn off" : "Turn on"} ${d.name}`, onclick: () => change("PATCH", f.id, { on: !f.on }) },
        el("span"),
      ),
    ),
    el(
      "div",
      { class: "fault-bottom" },
      el("span", { class: d.active ? "active" : "" }, d.status),
      el("button", { type: "button", class: "link", onclick: () => change("DELETE", f.id) }, "Remove"),
    ),
  );
}

async function change(method, id, body) {
  try {
    await send(method, `/api/faults/${encodeURIComponent(id)}`, body);
    await loadFaults();
  } catch (err) {
    showError(err);
  }
}

// --- Adding a preset ---

function showPresets() {
  const presets = state.catalogue.presets;
  show(
    $("presets"),
    presets.map((p) =>
      el(
        "button",
        {
          type: "button",
          class: "choice",
          "aria-pressed": String(p.id === state.picked),
          onclick: () => {
            state.picked = p.id;
            showPresets();
          },
        },
        el("strong", {}, p.name),
        el("small", {}, p.hint),
      ),
    ),
  );
  const setting = presetSetting(presets.find((p) => p.id === state.picked));
  $("setting").hidden = setting === null;
  if (setting) {
    show($("setting-label"), setting.label);
    const input = $("add-form").elements.setting;
    const integer = setting.field === "kb";
    input.dataset.number = integer ? "integer" : "decimal";
    input.inputMode = integer ? "numeric" : "decimal";
    if (input.dataset.for !== state.picked) {
      input.value = setting.value;
      input.dataset.for = state.picked;
    }
  }
}

async function addPreset(event) {
  event.preventDefault();
  const form = $("add-form").elements;
  const preset = state.catalogue.presets.find((p) => p.id === state.picked);
  const setting = presetSetting(preset);
  const note = $("add-note");
  try {
    const fields = { preset: preset.id, ...where(form), ...often(form), user: form.user.value };
    if (setting) {
      fields[setting.field] = form.setting.value;
    }
    const added = await send("POST", "/api/faults", faultBody(fields));
    note.className = "note";
    show(note, `Turned on: ${added.name}.`);
    await loadFaults();
  } catch (err) {
    note.className = "note error";
    show(note, err.message);
  }
}

// --- What happened ---

async function loadActivity() {
  const activity = await get("/api/activity");
  if (activity.last_event === state.lastEvent) {
    return;
  }
  state.lastEvent = activity.last_event;
  state.lines = activity.lines;
  showActivity();
}

function showActivity() {
  const shown = state.lines.filter((l) => l.id > state.clearedAfter && (state.filter !== "problems" || isProblem(l)));
  const routine = shown.filter(isRoutine).length;
  const lines = state.routine ? shown : shown.filter((l) => !isRoutine(l));
  if (state.newestFirst) {
    lines.reverse();
  }
  $("no-lines").hidden = lines.length > 0;
  show($("lines"), lines.map(lineItem));
  show($("filter-routine"), state.routine ? `Hide routine checks (${routine})` : `Show routine checks (${routine})`);
  const sort = $("sort");
  show(sort, state.newestFirst ? "Time ↓" : "Time ↑");
  sort.setAttribute("aria-label", state.newestFirst ? "Time, newest first. Show oldest first" : "Time, oldest first. Show newest first");
}

// storedOrder returns the order the viewer chose last, newest first unless
// they chose otherwise. Storage may be unavailable, as in a private window.
function storedOrder() {
  try {
    return localStorage.getItem("sftpit.order") !== "oldest";
  } catch {
    return true;
  }
}

function toggleOrder() {
  state.newestFirst = !state.newestFirst;
  try {
    localStorage.setItem("sftpit.order", state.newestFirst ? "newest" : "oldest");
  } catch {
    // The order still changes for this page.
  }
  showActivity();
}

function lineItem(line) {
  const d = describeLine(line);
  const tone = d.tone === "fault" || d.tone === "error" ? d.tone : "";
  const content = [
    el("span", { class: "time" }, formatClock(line.time)),
    el(
      "span",
      { class: "body" },
      el("span", { class: "headline" }, el("span", { class: "verb" }, d.verb), d.what && el("span", { class: "what" }, d.what), d.detail && el("span", { class: "detail" }, d.detail)),
      d.notes.map((n) => el("span", { class: "line-note" }, n)),
    ),
    el("span", { class: `badge ${d.tone}` }, d.badge),
  ];
  // A line with no requests behind it, such as a disconnection, has
  // nothing to expand.
  if (line.requests.length === 0) {
    return el("li", {}, el("div", { class: `row ${tone}` }, content, el("span", { class: "chevron" })));
  }
  const expanded = state.expanded.has(line.id);
  const toggle = () => {
    if (expanded) {
      state.expanded.delete(line.id);
    } else {
      state.expanded.add(line.id);
    }
    showActivity();
  };
  return el(
    "li",
    {},
    el(
      "button",
      { type: "button", class: `row ${tone}`, "aria-expanded": String(expanded), onclick: toggle },
      content,
      el("span", { class: "chevron", "aria-hidden": "true" }, "▾"),
    ),
    expanded && requestList(line),
  );
}

function requestList(line) {
  return el(
    "div",
    { class: "requests" },
    el("h3", {}, "What the client asked the server"),
    el(
      "ol",
      {},
      line.requests.map((r) => {
        const d = describeRequest(r);
        return el(
          "li",
          { class: `request ${d.tone === "fault" ? "fault" : ""}` },
          el("span", { class: "plain" }, el("span", {}, d.plain), el("code", {}, d.tech)),
          el("span", { class: `result ${d.tone}` }, d.result),
          el("span", { class: "took" }, d.duration),
          d.step && el("button", { type: "button", class: "make-fail", onclick: () => makeThisFail(r, d, line) }, "Make this fail"),
        );
      }),
    ),
  );
}

function setFilter(filter) {
  state.filter = filter;
  $("filter-all").setAttribute("aria-pressed", String(filter === "all"));
  $("filter-problems").setAttribute("aria-pressed", String(filter === "problems"));
  showActivity();
}

// --- A custom fault ---

function makeThisFail(r, d, line) {
  state.custom = { steps: new Set([d.step]), do: "refuse", from: `Based on “${d.plain}” at ${formatClock(line.time)}.` };
  const form = $("custom-form").elements;
  const file = r.path && !["connect", "authenticate", "list"].includes(d.step);
  form.where.value = file ? "file" : "any";
  form.file.value = file ? r.path : "";
  form.often.value = "every";
  form.after.value = "";
  location.hash = "#custom";
}

function showCustom() {
  const { steps, actions, errors } = state.catalogue;
  const c = state.custom;
  show($("custom-from"), c.from || "Choose the requests to act on, what to do, and which files.");
  show(
    $("steps"),
    steps.map((s) =>
      el(
        "button",
        {
          type: "button",
          class: "choice",
          "aria-pressed": String(c.steps.has(s.id)),
          onclick: () => {
            if (c.steps.has(s.id)) {
              c.steps.delete(s.id);
            } else {
              c.steps.add(s.id);
            }
            showCustom();
          },
        },
        el("strong", {}, s.name),
        el("code", {}, s.id),
      ),
    ),
  );
  show(
    $("actions"),
    actions.map((a) =>
      el(
        "div",
        { class: a.id === c.do ? "action on" : "action" },
        el(
          "label",
          {},
          el("input", {
            type: "radio",
            name: "do",
            value: a.id,
            checked: a.id === c.do,
            onchange: () => {
              c.do = a.id;
              showCustom();
            },
          }),
          a.name,
        ),
        a.id === c.do && actionSetting(a.id, errors),
      ),
    ),
  );
  updateSummary();
}

// actionSetting returns the field of an action's setting, if it has one.
function actionSetting(action, errors) {
  if (action === "refuse") {
    return el("label", { class: "setting" }, "Error", el("select", { name: "error", onchange: updateSummary }, errors.map((e) => el("option", { value: e, selected: e === "permission_denied" }, e.replaceAll("_", " ")))));
  }
  const fields = {
    wait: ["seconds", "Seconds", "3"],
    hold: ["seconds", "At most (seconds)", "600"],
    freeze: ["seconds", "For up to (seconds)", "60"],
    down: ["seconds", "For (seconds)", "30"],
    stop_partway: ["kb", "After (KB)", "32"],
  }[action];
  if (!fields) {
    return null;
  }
  const [name, label, value] = fields;
  const kind = name === "kb" ? "integer" : "decimal";
  return el(
    "label",
    { class: "setting" },
    label,
    el("input", { name, value, "data-number": kind, inputmode: kind === "integer" ? "numeric" : "decimal", class: "short", oninput: updateSummary }),
  );
}

function customFields() {
  const form = $("custom-form").elements;
  return {
    steps: [...state.custom.steps],
    do: state.custom.do,
    error: form.error?.value,
    seconds: form.seconds?.value,
    kb: form.kb?.value,
    after: form.after.value === "after",
    ...where(form),
    ...often(form),
    user: form.user.value,
  };
}

// where and often return the Which files and How often options a form has
// chosen, each with the value in that option's own field.
function where(form) {
  const chosen = form.where.value;
  return { where: chosen, place: form[chosen]?.value };
}

function often(form) {
  const chosen = form.often.value;
  return { often: chosen, count: form[chosen]?.value };
}

// setUpOptions makes the field of each of a form's options choose that
// option as it is typed in, and keeps "time" or "minute" agreeing with a
// number.
function setUpOptions(form) {
  for (const option of form.querySelectorAll(".options label")) {
    const radio = option.querySelector('input[type="radio"]');
    const number = option.querySelector('input:not([type="radio"])');
    if (!number) {
      continue;
    }
    const word = option.querySelector("[data-plural]");
    const agree = () => {
      if (word) {
        const singular = word.dataset.plural === "first" ? "time" : "minute";
        show(word, Number(number.value) === 1 ? singular : `${singular}s`);
      }
    };
    const choose = () => {
      if (!radio.checked) {
        radio.checked = true;
        form.dispatchEvent(new Event("input"));
      }
    };
    number.addEventListener("focus", choose);
    number.addEventListener("input", () => {
      choose();
      agree();
    });
    agree();
  }
}

function updateSummary() {
  const note = $("custom-note");
  show(note);
  try {
    show($("custom-summary"), summarise(faultBody(customFields()), state.catalogue.steps));
  } catch (err) {
    show($("custom-summary"), err.message);
  }
}

async function addCustom(event) {
  event.preventDefault();
  const note = $("custom-note");
  try {
    await send("POST", "/api/faults", faultBody(customFields()));
    state.custom = { steps: new Set(["remove"]), do: "refuse", from: "" };
    await loadFaults();
    location.hash = "#faults";
  } catch (err) {
    note.className = "note error";
    show(note, err.message);
  }
}

// --- Files ---

async function loadFiles() {
  try {
    const { files } = await get("/api/files");
    show($("file-rows"), treeRows(files.filter((f) => f.path !== "/")).map(fileRow));
  } catch (err) {
    showError(err);
  }
}

function fileRow({ file, depth, name }) {
  const dir = file.type === "dir";
  let tag = null;
  if (file.seed === "changed") {
    tag = el("span", { class: "tag changed" }, "changed");
  } else if (!dir && file.seed === undefined) {
    tag = el("span", { class: "tag new" }, "new");
  }
  const changed = new Date(file.mtime);
  const today = changed.toDateString() === new Date().toDateString();
  return el(
    "tr",
    {},
    el("td", { class: depth > 0 ? `indent-${Math.min(depth, 3)}` : "" }, el("code", {}, dir ? `${name}/` : name), tag),
    el("td", {}, dir ? "" : formatBytes(file.size)),
    el("td", {}, today ? formatClock(file.mtime) : changed.toLocaleDateString()),
    el("td", {}, dir ? "" : el("a", { href: `/api/files/content?path=${encodeURIComponent(file.path)}`, download: name }, "Download")),
  );
}

async function startAgain() {
  if (!confirm("Turn every fault off, delete what clients wrote and restore the starting files? Connected clients are disconnected.")) {
    return;
  }
  try {
    await send("POST", "/api/reset");
    state.faultsKey = "";
    await poll();
    await loadFiles();
  } catch (err) {
    showError(err);
  }
}

// --- Use from a test ---

function showExamples() {
  const api = `http://${location.host}/api`;
  show($("example-add"), `curl -X POST -H 'Sftpit-Control: 1' \\\n  ${api}/faults \\\n  -d '{"preset": "deletes_fail",\n       "folder": "/outgoing"}'\n\n{"id": "deletes-fail-1", "on": true,\n "happened": 0, …}`);
  show($("example-check"), `curl ${api}/faults/deletes-fail-1\n\n{"id": "deletes-fail-1", "on": true,\n "happened": 1, …}`);
  show($("example-reset"), `curl -X POST -H 'Sftpit-Control: 1' \\\n  ${api}/reset`);
}

// --- Start ---

async function start() {
  keepNumbers(document);
  $("add-form").addEventListener("submit", addPreset);
  setUpOptions($("add-form"));
  setUpOptions($("custom-form"));
  $("custom-form").addEventListener("submit", addCustom);
  $("custom-form").addEventListener("input", updateSummary);
  $("filter-all").addEventListener("click", () => setFilter("all"));
  $("filter-problems").addEventListener("click", () => setFilter("problems"));
  $("sort").addEventListener("click", toggleOrder);
  $("filter-routine").addEventListener("click", () => {
    state.routine = !state.routine;
    $("filter-routine").setAttribute("aria-pressed", String(state.routine));
    showActivity();
  });
  $("clear").addEventListener("click", () => {
    state.clearedAfter = state.lines.at(-1)?.id ?? state.clearedAfter;
    showActivity();
  });
  $("start-again").addEventListener("click", startAgain);
  $("release").addEventListener("click", () => send("POST", "/api/release").catch(showError));
  show($("files-lead"), "The files clients see. Start again turns every fault off, deletes what clients wrote and restores the starting files.");
  showExamples();
  try {
    [state.server, state.catalogue] = await Promise.all([get("/api/server"), get("/api/presets")]);
  } catch (err) {
    showError(err);
    setTimeout(start, pollInterval);
    return;
  }
  showServer(state.server);
  showPresets();
  window.addEventListener("hashchange", route);
  route();
  await poll();
  setInterval(poll, pollInterval);
}

start();
