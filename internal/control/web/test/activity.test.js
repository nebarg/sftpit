import { test } from "node:test";
import assert from "node:assert/strict";
import { describeLine, describeRequest, isProblem, isRoutine, plainReason } from "../activity.js";

const line = (fields) => ({ kind: "upload", outcome: "ok", requests: [], ...fields });

test("a line that worked reads as done", () => {
  const d = describeLine(line({ path: "/in/a.csv", bytes: 103657, duration_ms: 210 }));
  assert.deepEqual(d, { verb: "Uploaded", what: "/in/a.csv", detail: "101.2 KiB in 210 ms", tone: "ok", badge: "OK", notes: [] });
});

test("a line a fault caused names the fault", () => {
  const d = describeLine(line({ kind: "delete", outcome: "fault", path: "/out/r.csv", reason: "permission_denied", fault: { id: "deletes-fail-1", name: "Deletes fail" } }));
  assert.equal(d.verb, "Delete failed");
  assert.equal(d.detail, "permission denied");
  assert.equal(d.tone, "fault");
  assert.equal(d.badge, "Fault");
  assert.deepEqual(d.notes, ["Caused by the fault “Deletes fail”."]);
});

test("a failure sftpit did not cause is an error", () => {
  assert.equal(describeLine(line({ outcome: "failed", path: "/in/x.csv", reason: "no_such_file" })).detail, "no such file");
  const d = describeLine(line({ kind: "rename", outcome: "failed", path: "/a", target: "/b", reason: "no_such_file", read_only: "/ref" }));
  assert.equal(d.verb, "Rename failed");
  assert.equal(d.what, "/a → /b");
  assert.equal(d.tone, "error");
  assert.deepEqual(d.notes, ["Refused because /ref is read-only."]);
  assert.equal(isProblem(line({ outcome: "failed" })), true);
});

test("a check that finds nothing is an expected answer, not a problem", () => {
  const missing = line({ kind: "check", outcome: "failed", path: "/in/a.csv", reason: "no_such_file" });
  const d = describeLine(missing);
  assert.equal(d.verb, "Not found");
  assert.equal(d.tone, "quiet");
  assert.equal(d.badge, "Not found");
  assert.equal(isProblem(missing), false);
  assert.equal(isRoutine(line({ kind: "check", outcome: "ok" })), true);
  assert.equal(isRoutine(missing), false);
});

test("a transfer still going says so", () => {
  const d = describeLine(line({ kind: "download", in_progress: true, path: "/out/a.csv" }));
  assert.equal(d.verb, "Downloading");
  assert.equal(d.badge, "In progress");
  assert.equal(d.detail, "");
});

test("a repeated download says when the file was downloaded before", () => {
  const d = describeLine(line({ kind: "download", bytes: 10, repeat: { id: 3, time: "2026-11-12T10:42:06Z" } }));
  assert.match(d.notes[0], /^This file was also downloaded at \d\d:\d\d:06\.$/);
});

test("connections say who, from where and with which client", () => {
  assert.equal(
    describeLine(line({ kind: "connected", user: "test", remote: "127.0.0.1:50000", client: "SSH-2.0-OpenSSH_10.3" })).detail,
    "as test, from 127.0.0.1, client SSH-2.0-OpenSSH_10.3",
  );
  assert.equal(describeLine(line({ kind: "disconnected", user: "test", duration_ms: 41000 })).detail, "test, after 41.0 s");
  assert.equal(describeLine(line({ kind: "connection_failed", outcome: "fault", remote: "[::1]:5", fault: { name: "Logins fail" } })).verb, "Connection ended before login");
});

test("requests read in plain words, with what a custom fault would act on", () => {
  assert.deepEqual(describeRequest({ request: "remove", path: "/out/r.csv", reply: "permission_denied", outcome: "fault", duration_ms: 0.4 }), {
    plain: "Delete the file",
    tech: "remove /out/r.csv",
    result: "Refused: permission denied",
    tone: "fault",
    duration: "0.4 ms",
    step: "remove",
  });
  assert.deepEqual(describeRequest({ request: "write", path: "/in/a.csv", count: 4, bytes: 131072, reply: "ok", outcome: "ok" }), {
    plain: "Write data, 4 pieces, 128.0 KiB",
    tech: "write /in/a.csv",
    result: "OK",
    tone: "ok",
    duration: "",
    step: "write",
  });
  assert.equal(describeRequest({ request: "readdir", reply: "eof", outcome: "ok" }).result, "End");
  assert.equal(describeRequest({ request: "readdir", reply: "eof", outcome: "ok" }).step, "list");
  assert.equal(describeRequest({ request: "rename", path: "/a", target: "/b", reply: "ok", outcome: "ok" }).tech, "rename /a → /b");
  assert.equal(describeRequest({ request: "realpath", reply: "no_such_file", outcome: "failed" }).step, null);
  assert.equal(describeRequest({ request: "write", reply: "ok", outcome: "fault" }).result, "Changed by a fault");
  assert.equal(plainReason("connection_closed"), "the connection closed");
});
