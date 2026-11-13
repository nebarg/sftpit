import { test } from "node:test";
import assert from "node:assert/strict";
import { cleanNumber } from "../number.js";

test("an integer keeps only its digits", () => {
  assert.deepEqual(cleanNumber("12", "integer"), { value: "12", caret: 2 });
  assert.deepEqual(cleanNumber("1a2-b", "integer"), { value: "12", caret: 2 });
  assert.deepEqual(cleanNumber("3.5", "integer"), { value: "35", caret: 2 });
  assert.deepEqual(cleanNumber("", "integer"), { value: "", caret: 0 });
});

test("a decimal keeps its digits and its first point", () => {
  assert.deepEqual(cleanNumber("1.5", "decimal"), { value: "1.5", caret: 3 });
  assert.deepEqual(cleanNumber("1.5.2", "decimal"), { value: "1.52", caret: 4 });
  assert.deepEqual(cleanNumber("2e3", "decimal"), { value: "23", caret: 2 });
  assert.deepEqual(cleanNumber("-0,5", "decimal"), { value: "05", caret: 2 });
});

test("the caret stays after what was typed before it", () => {
  // "1x|2": typing x between 1 and 2 leaves the caret after the 1.
  assert.deepEqual(cleanNumber("1x2", "integer", 2), { value: "12", caret: 1 });
  assert.deepEqual(cleanNumber("12x", "integer", 3), { value: "12", caret: 2 });
  assert.deepEqual(cleanNumber("a12", "integer", 1), { value: "12", caret: 0 });
});
