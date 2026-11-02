import { test } from "node:test";
import assert from "node:assert/strict";
import { treeRows } from "../tree.js";

const dir = (path) => ({ path, type: "dir" });
const file = (path) => ({ path, type: "file" });

test("each directory is followed by what it holds, directories first", () => {
  const rows = treeRows([dir("/"), dir("/a"), file("/a-b"), file("/a/z"), dir("/a/y"), file("/a/y/x"), file("/b")]);
  assert.deepEqual(rows.map((r) => [r.file.path, r.depth, r.name]), [
    ["/", 0, "/"],
    ["/a", 1, "a"],
    ["/a/y", 2, "y"],
    ["/a/y/x", 3, "x"],
    ["/a/z", 2, "z"],
    ["/a-b", 1, "a-b"],
    ["/b", 1, "b"],
  ]);
});

test("a listing of a subdirectory starts at its depth", () => {
  const rows = treeRows([dir("/in"), file("/in/b"), file("/in/a")]);
  assert.deepEqual(rows.map((r) => [r.file.path, r.depth]), [["/in", 0], ["/in/a", 1], ["/in/b", 1]]);
});
