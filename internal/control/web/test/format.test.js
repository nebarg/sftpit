import { test } from "node:test";
import assert from "node:assert/strict";
import { formatBytes, formatClock, formatDuration } from "../format.js";

test("formatBytes uses binary units past 1023 bytes", () => {
  assert.equal(formatBytes(0), "0 B");
  assert.equal(formatBytes(1023), "1023 B");
  assert.equal(formatBytes(1024), "1.0 KiB");
  assert.equal(formatBytes(1536 * 1024), "1.5 MiB");
  assert.equal(formatBytes(2 ** 50), "1024.0 TiB");
});

test("formatDuration picks a precision for the size", () => {
  assert.equal(formatDuration(0.402), "0.4 ms");
  assert.equal(formatDuration(12.6), "13 ms");
  assert.equal(formatDuration(1500), "1.5 s");
  assert.equal(formatDuration(125000), "2 min 5 s");
});

test("formatClock gives the time of day", () => {
  assert.equal(formatClock("2026-11-12T10:42:07.5Z", "UTC"), "10:42:07");
  assert.equal(formatClock("2026-11-12T23:59:59Z", "Europe/London"), "23:59:59");
});
