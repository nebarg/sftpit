import { test } from "node:test";
import assert from "node:assert/strict";
import { cleanScenarioName, describeScenario, scenarioBody } from "../scenarios.js";

test("a scenario reads as where it is defined and its faults", () => {
  const light = { name: "unreliable-light", source: "built_in", on: false, description: "Unreliable server, light.", faults: [{}, {}] };
  assert.deepEqual(describeScenario(light), { name: "unreliable-light", description: "Unreliable server, light.", about: "Built in · 2 faults", error: "", deletable: false });
  assert.equal(describeScenario({ name: "own", source: "config", faults: [{}] }).about, "From the config file · 1 fault");
  assert.equal(describeScenario({ name: "own", source: "config", faults: [{}] }).description, "");
  const saved = describeScenario({ name: "mine", source: "file", faults: [{}, {}, {}] });
  assert.equal(saved.about, "Saved · 3 faults");
  assert.equal(saved.deletable, true);
  const broken = describeScenario({ name: "bad", source: "file", faults: [], error: "invalid scenario: faults[0]: there is no step" });
  assert.equal(broken.about, "Saved");
  assert.equal(broken.error, "invalid scenario: faults[0]: there is no step");
});

test("a scenario name keeps only what a name can hold", () => {
  assert.deepEqual(cleanScenarioName("Partner B_trouble!"), { value: "partner-b-trouble", caret: 17 });
  assert.deepEqual(cleanScenarioName("--x"), { value: "x", caret: 1 });
  assert.deepEqual(cleanScenarioName("a.b", 2), { value: "ab", caret: 1 });
  assert.deepEqual(cleanScenarioName("éclair 2"), { value: "clair-2", caret: 7 });
});

test("the faults that are on become a scenario's body", () => {
  const faults = [
    { id: "deletes-fail-1", on: true, happened: 3, name: "Deletes fail", preset: "deletes_fail", steps: ["remove"], do: "refuse", error: "permission_denied" },
    { id: "slow-1", on: false, happened: 0, name: "Slow", steps: ["list"], do: "wait", seconds: 2 },
    { id: "commands-fail-2", on: true, happened: 0, scenario: "unreliable-light", name: "Commands fail", steps: ["list"], do: "refuse", error: "failure", percent: 1 },
  ];
  assert.deepEqual(scenarioBody(faults, "  Partner trouble. "), {
    description: "Partner trouble.",
    faults: [
      { name: "Deletes fail", preset: "deletes_fail", steps: ["remove"], do: "refuse", error: "permission_denied" },
      { name: "Commands fail", steps: ["list"], do: "refuse", error: "failure", percent: 1 },
    ],
  });
  assert.deepEqual(scenarioBody(faults.slice(0, 1), " "), { faults: [{ name: "Deletes fail", preset: "deletes_fail", steps: ["remove"], do: "refuse", error: "permission_denied" }] });
  assert.throws(() => scenarioBody(faults.slice(1, 2), ""), /Turn on at least one fault/);
});
