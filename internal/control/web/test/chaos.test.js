import { test } from "node:test";
import assert from "node:assert/strict";
import { chaosOf, formOf } from "../chaos.js";

test("the switch gives chaos, paused chaos or none", () => {
  const form = { mode: "on", preset: "moderate", scope: "user", scope_value: " partner-b ", extras: ["wrong_size"] };
  assert.deepEqual(chaosOf(form), { preset: "moderate", scope: { user: "partner-b" }, extras: ["wrong_size"], paused: false });
  assert.deepEqual(chaosOf({ ...form, mode: "paused", scope: "" }), { preset: "moderate", scope: {}, extras: ["wrong_size"], paused: true });
  assert.equal(chaosOf({ ...form, mode: "off" }), null);
  assert.throws(() => chaosOf({ ...form, scope: "filename", scope_value: "" }), /Give a filename/);
});

test("a run's chaos fills the switch, and gives the same chaos back", () => {
  const chaos = { preset: "heavy", scope: { path_prefix: "/in" }, extras: ["corrupt_download"], paused: true };
  assert.deepEqual(formOf(chaos), { mode: "paused", preset: "heavy", scope: "path_prefix", scope_value: "/in", extras: ["corrupt_download"] });
  assert.deepEqual(chaosOf(formOf(chaos)), chaos);
  assert.deepEqual(formOf(null), { mode: "off", preset: "light", scope: "", scope_value: "", extras: [] });
  assert.deepEqual(formOf({ preset: "light", scope: {}, extras: [], paused: false }).scope, "");
});
