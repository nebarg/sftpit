import { test } from "node:test";
import assert from "node:assert/strict";
import { hexDump, preview } from "../preview.js";

const bytes = (s) => new TextEncoder().encode(s);

test("text shows as text, however it is marked up", () => {
  assert.deepEqual(preview(bytes("id,total\n1,<b>2</b>\r\n\ttab"), 25), { kind: "text", text: "id,total\n1,<b>2</b>\r\n\ttab", truncated: false });
});

test("an empty file previews as empty", () => {
  assert.deepEqual(preview(new Uint8Array(0), 0), { kind: "empty", text: "", truncated: false });
});

test("binary and control characters show as hex", () => {
  assert.equal(preview(new Uint8Array([0x89, 0x50, 0x4e, 0x47]), 4).kind, "hex");
  assert.equal(preview(bytes("ESC\x1b[31m"), 8).kind, "hex");
  assert.equal(preview(bytes("nul\x00"), 4).kind, "hex");
});

test("a character cut off at the end of a truncated preview is dropped", () => {
  const euro = bytes("price: €");
  const cut = euro.subarray(0, euro.length - 1);
  assert.deepEqual(preview(cut, 100), { kind: "text", text: "price: ", truncated: true });
  assert.equal(preview(cut, cut.length).kind, "hex");
});

test("the hex dump has offsets, hex and printable ASCII", () => {
  const dump = hexDump(bytes("0123456789abcdef\x00Z"));
  assert.equal(dump, "00000000  30 31 32 33 34 35 36 37 38 39 61 62 63 64 65 66  |0123456789abcdef|\n00000010  00 5a                                            |.Z|");
});
