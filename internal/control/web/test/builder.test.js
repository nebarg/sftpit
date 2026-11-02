import { test } from "node:test";
import assert from "node:assert/strict";
import { catalogue, compileRule } from "../builder.js";

// form returns a builder form with every field empty but those given.
function form(fields) {
  return {
    id: "r", fault: "delay", user: "", key_fingerprint: "", location: "", location_value: "", operations: "",
    trigger: "every", attempts: "", occurrence: "", probability: "", at: "", from: "", until: "", anchor: "transfer",
    when: "", duration: "", status: "", mode: "", max_freeze: "", max_stall: "", cutoff: "", result: "",
    transform: "", offset: "", length: "", size_delta: "",
    ...fields,
  };
}

test("a delay on every match is a rule in the long form", () => {
  assert.deepEqual(compileRule(form({ id: " slow ", user: "partner-b", location: "path_prefix", location_value: "/out", operations: "stat, list", when: "before", duration: "1s-3s" })), {
    id: "slow",
    match: { user: "partner-b", path_prefix: "/out", operation: ["stat", "list"] },
    action: { type: "delay", when: "before", duration: { min: "1s", max: "3s" } },
  });
});

test("a fault without chosen operations acts on its default ones", () => {
  assert.deepEqual(compileRule(form({ fault: "failure", status: "failure" })).match, { operation: ["any"] });
  assert.deepEqual(compileRule(form({ fault: "wrong_size", size_delta: "-1024" })), {
    id: "r",
    match: { operation: ["stat", "lstat", "fstat", "list"] },
    action: { type: "wrong_size", size_delta: -1024 },
  });
});

test("the long form's triggers become its match, trigger and decision", () => {
  // Attempts count opens, so without chosen operations they match opens.
  assert.deepEqual(compileRule(form({ fault: "failure", trigger: "attempts", attempts: "2" })).match, {
    operation: ["open_read", "open_write"],
    attempt: { per: ["user", "path"], numbers: [1, 2] },
  });
  assert.deepEqual(compileRule(form({ fault: "failure", trigger: "occurrence", occurrence: "2, 3" })).match.occurrence, [2, 3]);
  assert.deepEqual(compileRule(form({ fault: "failure", trigger: "probability", probability: "0.25" })).decision, { probability: 0.25 });
  assert.deepEqual(compileRule(form({ fault: "stall", trigger: "window", from: "5s", until: "10s", anchor: "run", max_stall: "1m" })), {
    id: "r",
    match: { operation: ["any"] },
    trigger: { window: { from: "5s", until: "10s" }, anchor: "run" },
    action: { type: "stall", max_stall: "1m" },
  });
});

test("a drop at a moment of a connection has no operation or when", () => {
  assert.deepEqual(compileRule(form({ fault: "drop", trigger: "at", at: "2s", anchor: "connection", when: "before", mode: "rst" })), {
    id: "r",
    match: {},
    trigger: { at: "2s", anchor: "connection" },
    action: { type: "close_connection", mode: "rst" },
  });
  assert.deepEqual(compileRule(form({ fault: "freeze", trigger: "at", at: "0s-1s", anchor: "transfer", operations: "open_write" })).match, { operation: ["open_write"] });
});

test("partial transfers, corruption, random failures and missing files are recipes", () => {
  assert.deepEqual(compileRule(form({ fault: "partial_upload", location: "path", location_value: "/in/a.csv", trigger: "attempts", attempts: "1", cutoff: "1048576", result: "status", status: "failure" })), {
    id: "r",
    fail_upload: { path: "/in/a.csv", attempts: [1], after_bytes: 1048576, result: "status", status: "failure" },
  });
  assert.deepEqual(compileRule(form({ fault: "partial_download", trigger: "probability", probability: "0.5", cutoff: "10-20", result: "close_connection", mode: "rst" })), {
    id: "r",
    fail_download: { probability: 0.5, after_bytes: { min: 10, max: 20 }, result: "close_connection", mode: "rst" },
  });
  assert.deepEqual(compileRule(form({ fault: "corrupt_download", location: "filename", location_value: "orders.csv", transform: "flip_bytes", offset: "", length: "64" })), {
    id: "r",
    corrupt_download: { filename: "orders.csv", transform: "flip_bytes", offset: 0, length: 64 },
  });
  assert.deepEqual(compileRule(form({ fault: "corrupt_upload", transform: "truncate", offset: "5", length: "9" })), { id: "r", corrupt_upload: { transform: "truncate", offset: 5 } });
  assert.deepEqual(compileRule(form({ fault: "random_failures", trigger: "probability", probability: "0.1", operations: "open_read" })), {
    id: "r",
    fail_randomly: { operations: ["open_read"], probability: 0.1 },
  });
  assert.deepEqual(compileRule(form({ fault: "random_failures", trigger: "probability", probability: "0.1" })).fail_randomly.operations, ["any"]);
  assert.deepEqual(compileRule(form({ fault: "missing_file", location: "filename_glob", location_value: "*.done" })), { id: "r", missing_file: { filename_glob: "*.done" } });
});

test("a read-only path fails every write there", () => {
  assert.deepEqual(compileRule(form({ fault: "read_only", location: "path_prefix", location_value: "/ref" })), {
    id: "r",
    match: { path_prefix: "/ref", operation: ["open_write", "setstat", "remove", "mkdir", "rmdir", "rename"] },
    action: { type: "fail", when: "before", status: "permission_denied" },
  });
});

test("an incomplete form says what it lacks", () => {
  assert.throws(() => compileRule(form({ id: "" })), /ID/);
  assert.throws(() => compileRule(form({ duration: "" })), /Give the delay/);
  assert.throws(() => compileRule(form({ location: "path", location_value: " " })), /scope/);
  assert.throws(() => compileRule(form({ fault: "failure", trigger: "attempts", attempts: "0" })), /at least 1/);
  assert.throws(() => compileRule(form({ fault: "failure", trigger: "probability", probability: "half" })), /probability must be a number/);
  assert.throws(() => compileRule(form({ fault: "random_failures", trigger: "every" })), /cannot fire at every match/);
  assert.throws(() => compileRule(form({ fault: "explode" })), /no fault explode/);
  assert.throws(() => compileRule(form({ fault: "failure", trigger: "window", from: "1s", until: "2s", anchor: "transfer" })), /counts from the run or the connection/);
  assert.throws(() => compileRule(form({ fault: "drop", trigger: "at", at: "1s", anchor: "run", location: "path", location_value: "/a" })), /scope it only by user or key/);
  assert.throws(() => compileRule(form({ fault: "read_only", trigger: "attempts", attempts: "1" })), /cannot fire at the first attempts/);
});

test("every fault offers every match or a probability", () => {
  for (const [name, fault] of Object.entries(catalogue)) {
    assert.ok(fault.triggers.includes("probability"), name);
  }
});
