import { test } from "node:test";
import assert from "node:assert/strict";
import { checkWarning, describeAssertion, ruleOutcomes } from "../result.js";

test("an assertion says what it checks, as a report does", () => {
  const cases = [
    [{ type: "rule_fired", rule_id: "cut" }, "rule_fired cut, at least 1"],
    [{ type: "rule_fired", rule_id: "cut", at_least: 2 }, "rule_fired cut, at least 2"],
    [{ type: "rule_fired", rule_id: "cut", exactly: 0 }, "rule_fired cut, exactly 0"],
    [{ type: "rule_fired", rule_id: "cut", at_most: 2 }, "rule_fired cut, at most 2"],
    [{ type: "rule_fired", rule_id: "cut", at_least: 1, at_most: 2 }, "rule_fired cut, 1 to 2"],
    [{ type: "successful_operation", operation: "remove", path: "/a", at_least: 1 }, "successful_operation remove /a, at least 1"],
    [{ type: "successful_operation", operation: "rename", source: "/a", target: "/b", at_least: 1 }, "successful_operation rename /a to /b, at least 1"],
    [{ type: "successful_operation", operation: "rename", target: "/b", at_least: 1 }, "successful_operation rename to /b, at least 1"],
    [{ type: "successful_operation", operation: "rename", source: "/a", at_least: 1 }, "successful_operation rename from /a, at least 1"],
    [{ type: "file_equals_fixture", path: "/a", fixture: "f" }, "file_equals_fixture /a, fixture f"],
    [{ type: "file_hash", path: "/a", sha256: "abc" }, "file_hash /a, sha256 abc"],
    [{ type: "path_absent", path: "/a" }, "path_absent /a"],
  ];
  for (const [assertion, want] of cases) {
    assert.equal(describeAssertion(assertion), want);
  }
});

test("rules that never fired come first, each with its outcome", () => {
  const rules = {
    zebra: { matched: 2, selected: 1, fired: 1 },
    idle: { matched: 0, selected: 0, fired: 0 },
    alpha: { matched: 3, selected: 3, fired: 3 },
    close: { matched: 4, selected: 0, fired: 0 },
  };
  assert.deepEqual(
    ruleOutcomes(rules).map((r) => [r.id, r.outcome]),
    [
      ["close", "matched, never fired"],
      ["idle", "never matched"],
      ["alpha", "fired"],
      ["zebra", "fired"],
    ],
  );
  assert.deepEqual(ruleOutcomes({}), []);
});

test("the warning says that a check ends the run, and how long clients have", () => {
  assert.match(checkWarning("30s"), /ends this run/);
  assert.match(checkWarning("30s"), /30s to close/);
});
