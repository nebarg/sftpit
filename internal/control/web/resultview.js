// The result view: the run's assertions, checking them, and the verdict.

import { APIError, get, runPath, send } from "./api.js";
import { el, show } from "./dom.js";
import { formatBytes } from "./format.js";
import { checkWarning, describeAssertion, ruleOutcomes } from "./result.js";

const $ = (id) => document.getElementById(id);

let ctx;
// shown identifies what the view shows, which it shows again only when that
// changes, so that a poll never replaces the form under someone typing.
let shown = null;
let checking = false;

// setupResult wires the view to ctx: run(), the current run's ID, state(),
// its state, and changed(), which it calls once a run has been checked.
export function setupResult(context) {
  ctx = context;
  $("check-form").addEventListener("submit", check);
}

// loadResult shows the current run's assertions, or its verdict if it has
// one.
export async function loadResult() {
  if (checking) {
    return;
  }
  const run = ctx.run();
  try {
    const state = ctx.state();
    // Only a drained run can have a verdict.
    const [report, rules] = await Promise.all([state === "drained" ? reportOf(run) : null, get(runPath(run, "rules"))]);
    if (run !== ctx.run() || checking) {
      return;
    }
    const key = JSON.stringify([run, state, report !== null, rules.assertions]);
    if (key === shown) {
      return;
    }
    shown = key;
    showLinks(run, report);
    $("check-form").hidden = report !== null || state === "draining";
    show($("check-error"));
    if (report) {
      showVerdict(report);
    } else {
      showAssertions(rules.assertions ?? [], state);
    }
  } catch (err) {
    // A reset between the status and these requests makes the run stale;
    // the next poll follows the new one.
    if (!(err instanceof APIError && err.status === 409)) {
      ctx.showError(err);
    }
  }
}

// reportOf returns the report of run, or null if it has not been checked.
async function reportOf(run) {
  try {
    return await get(runPath(run, "report"));
  } catch (err) {
    if (err instanceof APIError && err.status === 404) {
      return null;
    }
    throw err;
  }
}

function showLinks(run, report) {
  show(
    $("result-links"),
    report ? el("a", { href: runPath(run, "report") }, "Download the report") : null,
    el("a", { href: runPath(run, "trace") }, "Download the trace"),
  );
}

function showAssertions(assertions, state) {
  const count = assertions.length;
  show(
    $("result-verdict"),
    el("p", { class: "verdict" }, el("strong", {}, state === "draining" ? "Clients are finishing." : "Not checked yet.")),
    el("p", { class: "muted" }, count === 0 ? "This run states no assertions, so a check can only fail: nothing would be checked. A scenario states them under assertions." : "A check ends the run, so do it once the application has finished."),
  );
  show($("result-assertions"), count === 0 ? [] : table(["Assertion"], assertions.map((a) => el("tr", {}, el("td", {}, describeAssertion(a))))));
  show($("result-evidence"));
}

function showVerdict(report) {
  show(
    $("result-verdict"),
    el("p", { class: `verdict ${report.passed ? "passed" : "failed"}` }, el("strong", {}, report.passed ? "Passed" : "Failed")),
    report.problems?.length ? el("ul", { class: "problems" }, report.problems.map((p) => el("li", {}, p))) : null,
    report.interactive ? el("p", { class: "muted" }, "The rules changed during the run, so another run of its scenario may not repeat it.") : null,
    el("p", { class: "muted" }, "This says what the server saw. Whether the application recovered is for its own tests. The Reset button starts the next run."),
  );
  show(
    $("result-assertions"),
    report.assertions.length === 0
      ? []
      : table(
          ["Result", "Assertion", "Found"],
          report.assertions.map((a) =>
            el("tr", {}, el("td", { class: a.passed ? "pass" : "fail" }, a.passed ? "pass" : "FAIL"), el("td", {}, a.description), el("td", {}, a.detail)),
          ),
        ),
  );
  const rules = ruleOutcomes(report.rules);
  const trace = report.trace.complete ? "complete" : `incomplete${report.trace.error ? `: ${report.trace.error}` : ", at events.max_disk_bytes"}`;
  show(
    $("result-evidence"),
    el("h3", {}, "Rules"),
    rules.length === 0
      ? el("p", { class: "muted" }, "The run has no rules.")
      : table(
          ["Rule", number("Matched"), number("Selected"), number("Fired"), "Outcome"],
          rules.map((r) =>
            el(
              "tr",
              { class: r.fired > 0 ? "" : "idle" },
              el("td", {}, el("code", {}, r.id)),
              el("td", { class: "num" }, String(r.matched)),
              el("td", { class: "num" }, String(r.selected)),
              el("td", { class: "num" }, String(r.fired)),
              el("td", {}, r.outcome),
            ),
          ),
        ),
    el("h3", {}, "Final files"),
    report.files.length === 0
      ? el("p", { class: "muted" }, "The run left no files.")
      : table(
          ["Path", number("Size"), "SHA-256"],
          report.files.map((f) => el("tr", {}, el("td", {}, f.path), el("td", { class: "num" }, formatBytes(f.size)), el("td", {}, el("code", {}, f.sha256)))),
        ),
    el("p", { class: "muted" }, `Trace ${trace}, ${formatBytes(report.trace.bytes)}. Snapshots kept: ${report.snapshots}.`),
  );
}

// number marks a table's heading as that of a column of numbers.
function number(heading) {
  return { heading, class: "num" };
}

function table(headings, rows) {
  const head = headings.map((h) => el("th", { scope: "col", class: h.class }, h.heading ?? h));
  return el("div", { class: "scroll" }, el("table", {}, el("thead", {}, el("tr", {}, head)), el("tbody", {}, rows)));
}

async function check(ev) {
  ev.preventDefault();
  const timeout = $("check-form").elements.timeout.value.trim() || "10s";
  if (!confirm(checkWarning(timeout))) {
    return;
  }
  const button = $("check-form").querySelector("button");
  checking = true;
  button.disabled = true;
  show($("check-error"));
  show($("result-verdict"), el("p", { class: "verdict" }, el("strong", {}, `Waiting up to ${timeout} for clients to close their files…`)));
  let failure = null;
  try {
    await send("POST", runPath(ctx.run(), "assert"), { timeout });
  } catch (err) {
    failure = err.message;
  }
  checking = false;
  button.disabled = false;
  shown = null;
  ctx.changed();
  await loadResult();
  // Shown last, since showing the view again clears it.
  if (failure) {
    show($("check-error"), failure);
  }
}
