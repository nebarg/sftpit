import { test } from "node:test";
import assert from "node:assert/strict";
import { describeAction, describeChaos, describeMatch, ruleRows } from "../rules.js";

const cut = {
  id: "cut",
  priority: 10,
  max_triggers: 0,
  match: { operation: ["write"], path: "/in/a.csv", user: "test", attempt: { per: ["user", "path"], numbers: [1] } },
  action: { type: "partial_upload", cutoff_offset: 5, result: "status", status: "failure" },
};

test("a rule's match and action are spelt out", () => {
  assert.equal(describeMatch(cut), "write, /in/a.csv, user test, attempt 1 per user and path");
  assert.equal(describeAction(cut), "partial_upload, cutoff_offset 5, result status, status failure");
  const timed = {
    max_triggers: 2,
    match: { operation: ["rename"], source_prefix: "/in", target_filename_glob: "*.csv", occurrence: [2, 3] },
    trigger: { at: { min: "1s", max: "2s" }, anchor: "transfer" },
    decision: { probability: 0.5, scope: "operation" },
    action: { type: "delay", when: "before", duration: { min: "200ms", max: "3s" } },
  };
  assert.equal(describeMatch(timed), "rename, from under /in, to one named *.csv, occurrence 2, 3, at 1s–2s into the transfer, with probability 0.5 per operation, at most 2 times");
  assert.equal(describeAction(timed), "delay, when before, duration 200ms–3s");
  assert.equal(describeMatch({ match: {}, action: { type: "hide" } }), "any operation");
});

test("rows show what each rule did, chaos's after the run's own", () => {
  const rows = ruleRows({
    faults: [cut, { id: "idle", priority: 0, match: { operation: ["stat"] }, action: { type: "hide" } }],
    counts: { cut: { matched: 3, selected: 1, fired: 1, canceled: 0 }, "chaos-fail": { matched: 9, selected: 0, fired: 0, canceled: 0 } },
  });
  assert.deepEqual(rows.map((r) => [r.id, r.chaos, r.neverMatched, r.counts.matched]), [
    ["cut", false, false, 3],
    ["idle", false, true, 0],
    ["chaos-fail", true, false, 9],
  ]);
});

test("chaos is spelt out with its scope", () => {
  assert.equal(describeChaos({ preset: "heavy", scope: { user: "partner-b", path_prefix: "/in" }, extras: ["wrong_size"], paused: true }), "heavy chaos with wrong_size for user partner-b, path prefix /in, paused");
  assert.equal(describeChaos({ preset: "light", scope: {}, extras: [], paused: false }), "light chaos for everyone");
});
