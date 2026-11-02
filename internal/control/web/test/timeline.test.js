import { test } from "node:test";
import assert from "node:assert/strict";
import { Timeline, eventQuery } from "../timeline.js";

test("the timeline keeps the newest entries within its limit", () => {
  const t = new Timeline(3);
  for (let id = 1; id <= 5; id++) {
    assert.equal(t.add({ id }), true);
  }
  assert.deepEqual(t.entries.map((e) => e.event.id), [5, 4, 3]);
  assert.equal(t.dropped, 2);
});

test("an event sent again after a reconnection is not added twice", () => {
  const t = new Timeline(10);
  t.add({ id: 1 });
  t.add({ id: 2 });
  assert.equal(t.add({ id: 2 }), false);
  assert.equal(t.add({ id: 1 }), false);
  assert.equal(t.entries.length, 2);
});

test("a gap is an entry in its place", () => {
  const t = new Timeline(10);
  t.add({ id: 1 });
  t.gap(1, 40);
  t.add({ id: 40 });
  assert.deepEqual(t.entries[1], { gap: { after: 1, firstId: 40 } });
});

test("the event query leaves out filters not set", () => {
  assert.equal(eventQuery({}), "");
  assert.equal(eventQuery({ kind: "fault,operation", user: " test ", path: "", connection: "3", rule: "cut" }), "kind=fault%2Coperation&user=test&connection=3&rule=cut");
});
