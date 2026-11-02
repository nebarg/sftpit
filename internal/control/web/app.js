// The dashboard: the current run, how to connect, and the run's events,
// files and rules. It follows the current run, so after a reset it shows
// the next one.

import { APIError, get, runPath, send } from "./api.js";
import { connectCommands, loginMethods } from "./connection.js";
import { el, show } from "./dom.js";
import { loadChaos, loadScenarios, removeRule, setup, showQueued } from "./edit.js";
import { describeEvent, formatBytes, formatDuration, formatElapsed } from "./format.js";
import { preview, previewBytes } from "./preview.js";
import { describeChaos, ruleRows } from "./rules.js";
import { eventQuery, Timeline } from "./timeline.js";
import { treeRows } from "./tree.js";

// timelineLimit bounds the events the page keeps.
const timelineLimit = 2000;

// pollInterval is how often the page asks for the status, and for the
// rules while they are shown, whose counts change without an event.
const pollInterval = 2000;

const $ = (id) => document.getElementById(id);

const state = {
  status: null,
  server: null,
  run: null,
  tab: "activity",
  filters: {},
  timeline: new Timeline(timelineLimit),
  // rulesKey identifies the rules the rules table shows.
  rulesKey: null,
  stream: null,
  selectedFile: null,
};

// --- Errors ---

function showError(err) {
  const banner = $("error");
  if (err === null) {
    banner.hidden = true;
    return;
  }
  show(banner, err instanceof APIError ? err.message : `The control API cannot be reached: ${err.message}`);
  banner.hidden = false;
}

// --- Status and the current run ---

async function poll() {
  try {
    const status = await get("/api/v1/status");
    showError(null);
    showStatus(status);
    if (status.run.id !== state.run) {
      followRun(status.run.id);
    } else if (state.tab === "rules") {
      await loadRules();
    }
  } catch (err) {
    showError(err);
    show($("state"), "unreachable");
    $("state").className = "pill bad";
  }
}

// refreshStatus asks for the status once, however many events ask for it
// in the same frame.
let statusRefresh = false;
function refreshStatus() {
  if (!statusRefresh) {
    statusRefresh = true;
    requestAnimationFrame(() => {
      statusRefresh = false;
      poll();
    });
  }
}

function showStatus(status) {
  state.status = status;
  const sftp = status.sftp;
  const pill = $("state");
  show(pill, sftp.state);
  pill.className = `pill ${sftp.state === "up" ? "good" : sftp.state === "resetting" ? "" : "bad"}`;
  show($("run-id"), status.run.id);

  const run = status.run;
  const scenario = run.inline ? "inline" : run.scenario || "none";
  const facts = [
    ["Run", run.id],
    ["Scenario", scenario],
    ["Seed", `${run.seed}${run.seed_pinned ? " (pinned)" : " (fresh)"}`],
    ["Rules revision", String(run.revision)],
    ["Stalled", String(run.stalled)],
    ["Frozen", String(run.frozen)],
    ["Next reset", status.queued ? "starts with the queued rules" : "repeats this scenario"],
  ];
  if (sftp.state === "down") {
    facts.push(["Down until", new Date(sftp.down_until).toLocaleTimeString()]);
  }
  if (sftp.error) {
    facts.push(["Error", sftp.error]);
  }
  show($("run"), facts.flatMap(([k, v]) => [el("dt", {}, k), el("dd", {}, v)]));
  $("release").disabled = run.stalled + run.frozen === 0;
}

function followRun(run) {
  state.run = run;
  state.selectedFile = null;
  openStream();
  loadRules();
  if (state.tab === "files") {
    loadFiles();
  }
}

// --- How to connect ---

async function loadServer() {
  const server = await get("/api/v1/server");
  state.server = server;
  const facts = [["SFTP address", server.sftp_address]];
  for (const c of connectCommands(server)) {
    facts.push([`Command, ${c.where}`, el("code", {}, c.command)]);
  }
  if (server.default_login) {
    facts.push(["Login", `user ${server.default_login.user}, password ${server.default_login.password}`]);
  } else {
    facts.push(["Users", el("ul", { class: "plain" }, server.users.map((u) => el("li", {}, `${u.name} (${loginMethods(u)}), home ${u.home}`)))]);
  }
  facts.push(["Host keys", el("ul", { class: "plain" }, server.host_keys.map((k) => el("li", {}, el("code", {}, `${k.type} ${k.fingerprint}`))))]);
  if (server.read_only.length > 0) {
    facts.push(["Read-only", server.read_only.map((r) => (r.users ? `${r.path_prefix} (${r.users.join(", ")})` : r.path_prefix)).join(", ")]);
  }
  facts.push(["Profile", server.profile], ["Workspace", server.workspace]);
  show($("connect"), facts.flatMap(([k, v]) => [el("dt", {}, k), el("dd", {}, v)]));
}

// --- The timeline ---

function openStream() {
  state.stream?.close();
  state.timeline = new Timeline(timelineLimit);
  show($("timeline"));
  const run = state.run;
  const query = eventQuery(state.filters);
  const source = new EventSource(runPath(run, "events") + (query ? `?${query}` : ""));
  state.stream = source;
  let pending = [];
  let scheduled = false;
  const flush = () => {
    scheduled = false;
    const rows = pending;
    pending = [];
    $("timeline").prepend(...rows.reverse().flat());
    trimTimeline();
  };
  const queue = (rows) => {
    pending.push(rows);
    if (!scheduled) {
      scheduled = true;
      requestAnimationFrame(flush);
    }
  };
  source.onmessage = (msg) => {
    const e = JSON.parse(msg.data);
    if (state.timeline.add(e)) {
      queue(eventRows(e));
      if (e.kind === "rules_changed") {
        loadRules();
      }
      // A wait that begins or ends changes the counts of stalls and
      // freezes, and an outage the state.
      if (e.kind === "fault" || e.kind === "fault_ended") {
        refreshStatus();
      }
    }
  };
  source.addEventListener("gap", (msg) => {
    const gap = JSON.parse(msg.data);
    state.timeline.gap(gap.after, gap.first_id);
    queue([el("tr", { class: "entry gap" }, el("td", { colspan: 5 }, `Events ${gap.after + 1} to ${gap.first_id - 1} are no longer kept.`))]);
  });
  source.addEventListener("end", () => {
    source.close();
    // The run has ended, so a reset has started the next one.
    poll();
  });
}

// trimTimeline removes the rows of the entries the timeline no longer
// keeps, the oldest, with their details if open.
function trimTimeline() {
  const keep = state.timeline.entries.length;
  const rows = $("timeline").querySelectorAll("tr.entry");
  for (let i = keep; i < rows.length; i++) {
    if (rows[i].nextElementSibling?.classList.contains("details")) {
      rows[i].nextElementSibling.remove();
    }
    rows[i].remove();
  }
  const dropped = state.timeline.dropped;
  show($("timeline-note"), dropped > 0 ? `Showing the latest ${keep} entries; ${dropped} older ones are not shown.` : "");
}

function eventRows(e) {
  const { tone, summary } = describeEvent(e);
  const filter = (name, value) =>
    el("button", { type: "button", class: "link", title: `Show only ${name} ${value}`, onclick: (ev) => { ev.stopPropagation(); setFilter(name, value); } }, String(value));
  const detail = [summary];
  if (e.duration_ms !== undefined) {
    detail.push(el("span", { class: "muted" }, ` ${formatDuration(e.duration_ms)}`));
  }
  const row = el(
    "tr",
    { class: `entry ${tone}`, tabindex: 0, "aria-expanded": "false", title: e.time },
    el("td", { class: "time" }, formatElapsed(e.elapsed_ms)),
    el("td", {}, e.connection ? filter("connection", e.connection) : ""),
    el("td", {}, e.user ? filter("user", e.user) : ""),
    el("td", {}, detail),
    el("td", {}, e.rule ? filter("rule", e.rule) : ""),
  );
  const toggle = () => {
    const open = row.nextElementSibling?.classList.contains("details");
    if (open) {
      row.nextElementSibling.remove();
    } else {
      const only = e.path ? el("p", {}, "Show only events on ", filter("path", e.path)) : null;
      row.after(el("tr", { class: "details" }, el("td", { colspan: 5 }, only, el("pre", {}, JSON.stringify(e, null, 2)))));
    }
    row.setAttribute("aria-expanded", String(!open));
  };
  row.addEventListener("click", toggle);
  row.addEventListener("keydown", (ev) => {
    if (ev.key === "Enter" || ev.key === " ") {
      ev.preventDefault();
      toggle();
    }
  });
  return [row];
}

function setFilter(name, value) {
  const form = $("filters");
  form.elements[name].value = value;
  applyFilters();
}

function applyFilters() {
  const form = $("filters");
  state.filters = Object.fromEntries(["kind", "user", "path", "connection", "rule"].map((n) => [n, form.elements[n].value]));
  if (state.run) {
    openStream();
  }
}

// --- Files ---

async function loadFiles() {
  const run = state.run;
  const hash = $("files-hash").checked;
  try {
    const [listing, snapshots] = await Promise.all([
      get(`${runPath(run, "files")}?hash=${hash}`),
      get(`${runPath(run, "snapshots")}?hash=${hash}`),
    ]);
    if (run !== state.run) {
      return;
    }
    showError(null);
    show($("files-note"), listing.live ? "The current run's files, as they are now." : "");
    show($("file-rows"), treeRows(listing.files).map((r) => fileRow(r)));
    show(
      $("snapshots"),
      snapshots.snapshots.length === 0
        ? el("li", { class: "muted" }, "None: no fault has left a file behind.")
        : snapshots.snapshots.map((s) =>
            el(
              "li",
              {},
              `${s.number}. ${s.path}, ${formatBytes(s.size)}${s.sha256 ? `, sha256 ${s.sha256}` : ""} `,
              el("a", { href: runPath(run, `snapshots/${s.number}/content`) }, "Download"),
            ),
          ),
    );
    if (state.selectedFile) {
      const still = listing.files.find((f) => f.path === state.selectedFile);
      if (still) {
        showFile(still);
      } else {
        state.selectedFile = null;
        show($("file-detail"));
      }
    }
  } catch (err) {
    showError(err);
  }
}

function fileRow({ file, depth, name }) {
  const label = file.type === "dir" ? `${name}${name === "/" ? "" : "/"}` : name;
  const nameCell =
    file.type === "dir"
      ? el("span", { class: "dir" }, label)
      : el("button", { type: "button", class: "link", onclick: () => showFile(file) }, label);
  const cell = el("td", {}, nameCell);
  // Set through the CSSOM, which the dashboard's policy allows, unlike a
  // style attribute.
  cell.style.paddingInlineStart = `${0.5 + depth * 1.25}rem`;
  return el(
    "tr",
    { class: file.path === state.selectedFile ? "selected" : "", "data-path": file.path },
    cell,
    el("td", { class: "num" }, file.type === "dir" ? "" : formatBytes(file.size)),
    el("td", {}, file.mode),
    el("td", { title: file.mtime }, new Date(file.mtime).toLocaleString()),
    el("td", { class: file.seed === "changed" ? "changed" : "" }, file.seed ?? ""),
  );
}

async function showFile(file) {
  state.selectedFile = file.path;
  const run = state.run;
  const url = `${runPath(run, "files/content")}?path=${encodeURIComponent(file.path)}`;
  const body = el("pre", { class: "preview" }, "Loading…");
  show(
    $("file-detail"),
    el("h3", {}, file.path),
    el(
      "p",
      {},
      `${formatBytes(file.size)}, mode ${file.mode}, modified ${new Date(file.mtime).toLocaleString()}`,
      file.sha256 ? [el("br"), `sha256 ${file.sha256}`] : [],
    ),
    el("p", {}, el("a", { href: url }, "Download")),
    body,
  );
  for (const tr of $("file-rows").children) {
    tr.classList.toggle("selected", tr.dataset.path === file.path);
  }
  try {
    const resp = await fetch(url, { headers: { Range: `bytes=0-${previewBytes - 1}` } });
    if (!resp.ok) {
      throw new APIError(resp.status, (await resp.json().catch(() => ({}))).error ?? resp.statusText);
    }
    const bytes = new Uint8Array(await resp.arrayBuffer());
    const total = Number(resp.headers.get("Content-Range")?.split("/")[1] ?? bytes.length);
    const p = preview(bytes, total);
    const note = p.truncated ? `\n\n… the first ${formatBytes(bytes.length)} of ${formatBytes(total)}` : "";
    show(body, p.kind === "empty" ? "(empty)" : p.text + note);
    body.className = `preview ${p.kind}`;
  } catch (err) {
    show(body, `No preview: ${err.message}`);
  }
}

// --- Rules ---

async function loadRules() {
  const run = state.run;
  try {
    const reply = await get(runPath(run, "rules"));
    if (run !== state.run) {
      return;
    }
    const banner = $("chaos-banner");
    if (reply.chaos && !reply.chaos.paused) {
      show(banner, `Chaos is on: ${describeChaos(reply.chaos)}. Failures may be deliberate.`);
      banner.hidden = false;
    } else {
      banner.hidden = true;
    }
    const chaos = reply.chaos ? ` Chaos: ${describeChaos(reply.chaos)}.` : "";
    show($("rules-note"), `Revision ${reply.revision}. Rules are tried in this order; a rule that has never matched is marked.${chaos}`);
    const rows = ruleRows(reply);
    // The table is shown again only when the rules change. Otherwise only
    // the counts change, in place, so that a button is never replaced
    // under a click on it.
    const key = JSON.stringify([run, rows.map((r) => [r.id, r.priority, r.match, r.action, r.chaos, r.neverMatched])]);
    if (key === state.rulesKey) {
      for (const r of rows) {
        const cells = $("rule-rows").querySelector(`tr[data-rule="${CSS.escape(r.id)}"]`)?.querySelectorAll("td.count") ?? [];
        ["matched", "selected", "fired", "canceled"].forEach((name, i) => cells[i] && show(cells[i], String(r.counts[name])));
      }
      await showQueued(state.status?.queued);
      return;
    }
    state.rulesKey = key;
    show(
      $("rule-rows"),
      rows.length === 0
        ? el("tr", {}, el("td", { colspan: 9, class: "muted" }, "No rules: sftpit injects no faults in this run."))
        : rows.map((r) =>
            el(
              "tr",
              { class: r.neverMatched ? "idle" : "", "data-rule": r.id },
              el("td", {}, el("code", {}, r.id), r.neverMatched ? el("span", { class: "tag" }, "never matched") : ""),
              el("td", { class: "num" }, r.priority ?? ""),
              el("td", {}, r.match),
              el("td", {}, r.action),
              el("td", { class: "num count" }, String(r.counts.matched)),
              el("td", { class: "num count" }, String(r.counts.selected)),
              el("td", { class: "num count" }, String(r.counts.fired)),
              el("td", { class: "num count" }, String(r.counts.canceled)),
              el("td", {}, r.chaos ? "" : el("button", { type: "button", title: `Remove ${r.id} from the current run`, onclick: () => removeRule(r.id) }, "Remove")),
            ),
          ),
    );
    await showQueued(state.status?.queued);
  } catch (err) {
    // A reset between the status and this request makes the run stale;
    // the next poll follows the new one.
    if (!(err instanceof APIError && err.status === 409)) {
      showError(err);
    }
  }
}

// --- Tabs ---

const tabs = ["activity", "files", "rules", "chaos", "builder", "scenarios"];

function selectTab(tab) {
  state.tab = tab;
  for (const name of tabs) {
    const selected = name === tab;
    $(`tab-${name}`).setAttribute("aria-selected", String(selected));
    $(`tab-${name}`).tabIndex = selected ? 0 : -1;
    $(name).hidden = !selected;
  }
  if (tab === "files") {
    loadFiles();
  } else if (tab === "rules") {
    loadRules();
  } else if (tab === "chaos") {
    loadChaos();
  } else if (tab === "scenarios") {
    loadScenarios();
  }
}

function onTabKey(ev) {
  const i = tabs.indexOf(state.tab);
  const next = { ArrowRight: tabs[(i + 1) % tabs.length], ArrowLeft: tabs[(i + tabs.length - 1) % tabs.length] }[ev.key];
  if (next) {
    selectTab(next);
    $(`tab-${next}`).focus();
  }
}

// --- Reset and release ---

async function openReset() {
  const dialog = $("reset-dialog");
  show($("reset-error"));
  show($("reset-what"), `Resetting ends run ${state.run}, closing its connections, and starts the next run from the seed. The run's files and events are kept with the last five runs.`);
  const select = $("reset-scenario");
  show(select, el("option", { value: "repeat" }, "Repeat the current scenario"), el("option", { value: "" }, "No faults"));
  try {
    const { scenarios } = await get("/api/v1/scenarios");
    for (const s of scenarios) {
      if (!s.error) {
        select.append(el("option", { value: `scenario:${s.name}` }, s.source === "file" ? `${s.name} (file)` : s.name));
      }
    }
  } catch (err) {
    show($("reset-error"), `The scenarios cannot be listed: ${err.message}`);
  }
  dialog.showModal();
}

async function submitReset(ev) {
  ev.preventDefault();
  const form = $("reset-form");
  const body = { run: state.run };
  const choice = form.elements.scenario.value;
  if (choice !== "repeat") {
    body.scenario = choice.replace(/^scenario:/, "");
  }
  const seed = form.elements.seed.value.trim();
  if (seed !== "") {
    body.seed = seed;
  }
  try {
    const status = await send("POST", "/api/v1/reset", body);
    $("reset-dialog").close();
    form.reset();
    showStatus(status);
    followRun(status.run.id);
  } catch (err) {
    show($("reset-error"), err.message);
  }
}

async function releaseStalls() {
  try {
    showStatus(await send("POST", runPath(state.run, "release-stalls")));
  } catch (err) {
    showError(err);
  }
}

// --- Start ---

$("reset").addEventListener("click", openReset);
$("reset-form").addEventListener("submit", submitReset);
$("reset-cancel").addEventListener("click", () => $("reset-dialog").close());
$("release").addEventListener("click", releaseStalls);
$("filters").addEventListener("submit", (ev) => {
  ev.preventDefault();
  applyFilters();
});
// A reset of the form clears its fields after this event.
$("filters").addEventListener("reset", () => setTimeout(applyFilters));
$("files-refresh").addEventListener("click", loadFiles);
$("files-hash").addEventListener("change", loadFiles);
for (const name of tabs) {
  $(`tab-${name}`).addEventListener("click", () => selectTab(name));
  $(`tab-${name}`).addEventListener("keydown", onTabKey);
}
setup({
  run: () => state.run,
  showError,
  changed: () => {
    poll();
    loadRules();
  },
});
selectTab("activity");
loadServer().catch(showError);
poll();
setInterval(poll, pollInterval);
