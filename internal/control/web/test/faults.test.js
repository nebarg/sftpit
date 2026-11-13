import { test } from "node:test";
import assert from "node:assert/strict";
import { describeFault, faultBody, presetSetting, summarise } from "../faults.js";

const steps = [
  { id: "remove", name: "Deleting a file" },
  { id: "rename", name: "Renaming or moving" },
];

test("a fault reads as what it does, where and how often", () => {
  const deletes = { id: "deletes-fail-1", on: true, happened: 2, name: "Deletes fail", steps: ["remove"], do: "refuse", error: "permission_denied", folder: "/outgoing" };
  assert.deepEqual(describeFault(deletes), { name: "Deletes fail", summary: "refused with “permission denied” · in /outgoing · every time", status: "Happened 2 times", active: true });
  assert.equal(describeFault({ ...deletes, happened: 0 }).status, "Not happened yet");
  assert.equal(describeFault({ ...deletes, happened: 1 }).status, "Happened once");
  assert.deepEqual(describeFault({ ...deletes, on: false }), { name: "Deletes fail", summary: "refused with “permission denied” · in /outgoing · every time", status: "Off", active: false });

  const slow = { on: true, happened: 0, name: "Slow responses", steps: ["list", "stat"], do: "wait", seconds: 3, user: "partner-b", percent: 25 };
  assert.equal(describeFault(slow).summary, "3 s slower · any file, for partner-b · 25% of the time");
  assert.equal(describeFault({ on: true, happened: 0, name: "Server goes down", do: "down", seconds: 30 }).summary, "down for 30 s · the whole server · every time");
  assert.equal(describeFault({ on: true, happened: 0, name: "Logins fail", steps: ["authenticate"], do: "drop", first: 1 }).summary, "every connection · first time only");
  assert.equal(describeFault({ on: true, happened: 0, name: "x", steps: ["write"], do: "stop_partway", kb: 32, names: "*.csv", only: 2 }).summary, "stops after 32 KB · names like *.csv · only time number 2");
  assert.equal(describeFault({ on: true, happened: 0, name: "x", steps: ["read"], do: "stop_partway", kb: 32, error: "failure" }).summary, "stops after 32 KB with “failure” · any file · every time");
  assert.equal(describeFault({ on: true, happened: 0, name: "x", steps: ["write"], do: "truncate", kb: 3072 }).summary, "cut short after 3072 KB · any file · every time");
});

test("a preset asks for its one setting", () => {
  assert.deepEqual(presetSetting({ fault: { do: "wait", seconds: 3 } }), { field: "seconds", label: "Extra seconds", value: "3" });
  assert.deepEqual(presetSetting({ fault: { do: "down", seconds: 30 } }), { field: "seconds", label: "Down for (seconds)", value: "30" });
  assert.deepEqual(presetSetting({ fault: { do: "stop_partway", kb: 32 } }), { field: "kb", label: "Stop after (KB)", value: "32" });
  assert.equal(presetSetting({ fault: { do: "refuse", error: "permission_denied" } }), null);
});

test("the forms' fields become the body of a new fault", () => {
  assert.deepEqual(faultBody({ preset: "deletes_fail", where: "folder", place: " /outgoing ", often: "every" }), { preset: "deletes_fail", folder: "/outgoing" });
  assert.deepEqual(faultBody({ preset: "slow_responses", seconds: "1.5", where: "any", often: "percent", count: "25" }), { preset: "slow_responses", seconds: 1.5, percent: 25 });
  assert.deepEqual(faultBody({ steps: ["remove"], do: "refuse", error: "no_such_file", after: true, where: "file", place: "/a", user: "partner-b", often: "first", count: "2" }), {
    steps: ["remove"],
    do: "refuse",
    error: "no_such_file",
    after: true,
    file: "/a",
    user: "partner-b",
    first: 2,
  });
  assert.deepEqual(faultBody({ steps: ["write"], do: "stop_partway", error: "failure", kb: "64", where: "any", often: "every" }), { steps: ["write"], do: "stop_partway", error: "failure", kb: 64 });
  assert.deepEqual(faultBody({ steps: ["write"], do: "stop_partway", error: "", kb: "64" }), { steps: ["write"], do: "stop_partway", kb: 64 });
  assert.deepEqual(faultBody({ steps: ["write"], do: "wait", error: "failure", seconds: "1" }), { steps: ["write"], do: "wait", seconds: 1 });
  assert.throws(() => faultBody({ steps: [], do: "refuse" }), /Choose at least one step/);
  assert.throws(() => faultBody({ preset: "deletes_fail", where: "names", place: "" }), /Give the name pattern/);
  assert.throws(() => faultBody({ preset: "deletes_fail", often: "first", count: "lots" }), /How often must be a number/);
  assert.throws(() => faultBody({ preset: "slow_responses", seconds: " " }), /The seconds must be a number/);
  assert.deepEqual(faultBody({ preset: "slow_responses", seconds: "" }), { preset: "slow_responses" });
});

test("minutes agree with their number", () => {
  const fault = (minutes) => describeFault({ on: false, happened: 0, name: "x", steps: ["remove"], do: "refuse", error: "failure", minutes }).summary;
  assert.match(fault(1), /for 1 minute$/);
  assert.match(fault(5), /for 5 minutes$/);
});

test("a custom fault reads as a sentence", () => {
  assert.equal(
    summarise({ steps: ["remove", "rename"], do: "refuse", error: "permission_denied", file: "/out/r.csv" }, steps),
    "When the client is deleting a file or renaming or moving (/out/r.csv), refuse with “permission denied”, before the server carries out the request, every time.",
  );
  assert.equal(summarise({ steps: ["remove"], do: "wait", seconds: 2, after: true, first: 1 }, steps), "When the client is deleting a file (any file), wait 2 s, after the server carries out the request, first time only.");
  const writes = [{ id: "write", name: "Writing file data" }];
  assert.equal(summarise({ steps: ["write"], do: "truncate", kb: 64 }, writes), "When the client is writing file data (any file), cut the file short after 64 KB, without an error, every time.");
  assert.equal(summarise({ steps: ["write"], do: "stop_partway", error: "failure", only: 1 }, writes), "When the client is writing file data (any file), stop after 32 KB, answering “failure”, only time number 1.");
});
