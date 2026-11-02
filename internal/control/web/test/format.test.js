import { test } from "node:test";
import assert from "node:assert/strict";
import { describeEvent, formatBytes, formatDuration, formatElapsed, isFailure, shortName } from "../format.js";

test("formatBytes uses binary units past 1023 bytes", () => {
  assert.equal(formatBytes(0), "0 B");
  assert.equal(formatBytes(1023), "1023 B");
  assert.equal(formatBytes(1024), "1.0 KiB");
  assert.equal(formatBytes(1536 * 1024), "1.5 MiB");
  assert.equal(formatBytes(2 ** 50), "1024.0 TiB");
});

test("formatElapsed gives minutes, seconds and milliseconds", () => {
  assert.equal(formatElapsed(0), "0:00.000");
  assert.equal(formatElapsed(62345.9), "1:02.345");
  assert.equal(formatElapsed(-5), "0:00.000");
});

test("formatDuration picks a precision for the size", () => {
  assert.equal(formatDuration(0.402), "0.4 ms");
  assert.equal(formatDuration(12.6), "13 ms");
  assert.equal(formatDuration(1500), "1.50 s");
});

test("replies other than OK and EOF are failures", () => {
  assert.equal(shortName("SSH_FXP_STAT"), "STAT");
  assert.equal(shortName("SSH_FX_FAILURE"), "FAILURE");
  assert.equal(isFailure("SSH_FX_FAILURE"), true);
  assert.equal(isFailure("SSH_FX_OK"), false);
  assert.equal(isFailure("SSH_FX_EOF"), false);
  assert.equal(isFailure("SSH_FXP_ATTRS"), false);
  assert.equal(isFailure(undefined), false);
});

test("an operation's tone tells an injected fault from the policy and a genuine failure", () => {
  const op = { kind: "operation", request: "SSH_FXP_STAT", path: "/a" };
  assert.deepEqual(describeEvent({ ...op, reply: "SSH_FX_FAILURE", backend_reply: "SSH_FXP_ATTRS", rule: "lie" }), {
    tone: "fault",
    summary: "STAT /a → FAILURE (backend: ATTRS)",
  });
  assert.deepEqual(describeEvent({ ...op, reply: "SSH_FX_PERMISSION_DENIED", read_only: "/ref" }), {
    tone: "policy",
    summary: "STAT /a → PERMISSION_DENIED, read-only /ref",
  });
  assert.equal(describeEvent({ ...op, reply: "SSH_FX_NO_SUCH_FILE", backend_reply: "SSH_FX_NO_SUCH_FILE" }).tone, "error");
  assert.deepEqual(describeEvent({ ...op, reply: "SSH_FXP_ATTRS", backend_reply: "SSH_FXP_ATTRS" }), { tone: "", summary: "STAT /a → ATTRS" });
  assert.equal(describeEvent({ kind: "operation", request: "SSH_FXP_RENAME", path: "/a", target: "/b", reply: "SSH_FX_OK" }).summary, "RENAME /a → /b → OK");
});

test("every kind of event has a summary", () => {
  const cases = [
    [{ kind: "run_started", run: { scenario: "flaky", seed: "7", seed_pinned: true } }, "notice", "Run started: scenario flaky, seed 7 (pinned)"],
    [{ kind: "run_started", run: { inline: true, seed: "8" } }, "notice", "Run started: an inline scenario, seed 8"],
    [{ kind: "run_started", run: { seed: "9" } }, "notice", "Run started: no scenario, seed 9"],
    [{ kind: "connected", connection: 3 }, "", "Connection 3 opened"],
    [{ kind: "authenticated", connection: 3, user: "partner-b", key_fingerprint: "SHA256:x" }, "", "Logged in as partner-b with key SHA256:x"],
    [{ kind: "disconnected", connection: 3 }, "", "Connection 3 closed"],
    [{ kind: "transfer", path: "/a", transfer: { mode: "write", writes: 2, bytes_written: 2048, closed: "close" } }, "", "Transfer of /a (write): 2 writes, 2.0 KiB, closed by close"],
    [{ kind: "transfer", path: "/a", transfer: { mode: "read", closed: "fault", faulted: true } }, "fault", "Transfer of /a (read): nothing read or written, closed by fault"],
    [{ kind: "fault", request: "SSH_FXP_WRITE", path: "/a", fault: { type: "partial_upload", when: "before" } }, "fault", "Injected partial_upload (before) on /a"],
    [{ kind: "fault", request: "connect", connection: 2, fault: { type: "freeze_connection" } }, "fault", "Injected freeze_connection on connect"],
    [{ kind: "fault_ended", fault: { type: "stall" }, reason: "released" }, "fault", "stall ended: released"],
    [{ kind: "suppressed", rule: "once", reason: "max_triggers" }, "", "Suppressed a fault of once: max_triggers"],
    [{ kind: "decision", rule: "flaky", decision: { choice: "probability", draw: 0.25, probability: 0.5, fired: true } }, "", "flaky drew 0.2500 against 0.5: fires"],
    [{ kind: "decision", rule: "slow", decision: { choice: "duration", draw: 0.5, value: "1.2s" } }, "", "slow drew 0.5000: duration 1.2s"],
    [{ kind: "rules_changed", rules: { revision: 2 } }, "notice", "Rules changed to revision 2"],
    [{ kind: "snapshot", path: "/a", snapshot: { size: 5, copy: "snapshots/1/a" } }, "notice", "Kept a copy of /a, 5 B"],
    [{ kind: "snapshot", path: "/a", snapshot: { size: 5 } }, "notice", "Kept a record of /a, 5 B"],
  ];
  for (const [event, tone, summary] of cases) {
    assert.deepEqual(describeEvent(event), { tone, summary }, event.kind);
  }
});
