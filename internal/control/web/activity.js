// How the activity feed reads: each line the API gives, and each request
// behind it, in plain words. Everything here returns plain strings, which
// the page sets as text, never as HTML.

import { formatBytes, formatClock, formatDuration } from "./format.js";

const reasons = {
  permission_denied: "permission denied",
  no_such_file: "no such file",
  failure: "failure",
  op_unsupported: "not supported",
  bad_message: "bad message",
  eof: "end of file",
  connection_closed: "the connection closed",
};

// plainReason returns a reply's reason in plain words.
export function plainReason(reason) {
  return reasons[reason] ?? reason?.replaceAll("_", " ") ?? "";
}

// verbs give each kind of line its verb when it worked, when it did not,
// and while it is still going.
const verbs = {
  connected: ["Connected", "Connection closed after login"],
  connection_failed: ["Connection ended before login", "Connection ended before login"],
  disconnected: ["Disconnected", "Disconnected"],
  upload: ["Uploaded", "Upload failed", "Uploading"],
  download: ["Downloaded", "Download failed", "Downloading"],
  open: ["Opened", "Open failed", "Open"],
  listing: ["Listed", "Listing failed", "Listing"],
  check: ["Checked", "Check failed"],
  delete: ["Deleted", "Delete failed"],
  rename: ["Renamed", "Rename failed"],
  mkdir: ["Made folder", "Making a folder failed"],
  rmdir: ["Deleted folder", "Deleting a folder failed"],
  setstat: ["Changed attributes", "Changing attributes failed"],
  realpath: ["Resolved a path", "Resolving a path failed"],
  statvfs: ["Checked free space", "Checking free space failed"],
  outage: ["Server went down", "Server went down"],
  fault: ["Fault", "Fault"],
  other: ["Request", "Request failed"],
};

// describeLine returns how a line shows: its verb, what it acted on, a
// short detail, its tone, which is "ok", "fault" for what a fault did on
// purpose, "error" for a failure sftpit did not cause, or "quiet" for an
// expected answer such as a missing file being checked for, the badge
// that says so, and notes that explain it.
export function describeLine(line) {
  const [worked, failed, going] = verbs[line.kind] ?? verbs.other;
  let verb = line.outcome === "ok" ? worked : failed;
  if (line.in_progress && going) {
    verb = going;
  }
  let tone = line.outcome === "fault" ? "fault" : line.outcome === "failed" ? "error" : "ok";
  if (line.kind === "check" && line.outcome === "failed" && line.reason === "no_such_file") {
    verb = "Not found";
    tone = "quiet";
  }
  const badge = { ok: "OK", fault: "Fault", error: "Failed", quiet: "Not found" }[tone];
  return {
    verb,
    what: line.target ? `${line.path} → ${line.target}` : (line.path ?? ""),
    detail: lineDetail(line),
    tone: line.in_progress ? "ok" : tone,
    badge: line.in_progress ? "In progress" : badge,
    notes: lineNotes(line),
  };
}

function lineDetail(line) {
  const parts = [];
  switch (line.kind) {
    case "connected":
      parts.push(`as ${line.user}`);
      if (line.remote) {
        parts.push(`from ${line.remote.replace(/:\d+$/, "")}`);
      }
      if (line.client) {
        parts.push(`client ${line.client}`);
      }
      return parts.join(", ");
    case "connection_failed":
      return line.remote ? `from ${line.remote.replace(/:\d+$/, "")}` : "";
    case "disconnected":
      return [line.user, line.duration_ms ? `after ${formatDuration(line.duration_ms)}` : ""].filter(Boolean).join(", ");
    case "upload":
    case "download":
      if (line.bytes || (line.outcome === "ok" && !line.in_progress)) {
        parts.push(formatBytes(line.bytes ?? 0));
      }
      if (line.duration_ms && !line.in_progress) {
        parts.push(`in ${formatDuration(line.duration_ms)}`);
      }
      break;
  }
  if (line.outcome !== "ok" && line.reason) {
    parts.push(plainReason(line.reason));
  }
  return parts.join(" ");
}

function lineNotes(line) {
  const notes = [];
  if (line.fault) {
    notes.push(`Caused by the fault “${line.fault.name}”.`);
  }
  if (line.read_only) {
    notes.push(`Refused because ${line.read_only} is read-only.`);
  }
  if (line.repeat) {
    notes.push(`This file was also downloaded at ${formatClock(line.repeat.time)}.`);
  }
  return notes;
}

// isProblem reports whether a line is something going wrong: a fault, or a
// failure that is not an expected answer.
export function isProblem(line) {
  const tone = describeLine(line).tone;
  return tone === "fault" || tone === "error";
}

// isRoutine reports whether a line is one that clients send as a matter of
// course and the feed hides unless asked: a check that found the file.
export function isRoutine(line) {
  return line.kind === "check" && line.outcome === "ok";
}

const requests = {
  connect: "Connect",
  authenticate: "Log in",
  open_write: "Start an upload",
  open_read: "Start a download",
  write: "Write data",
  read: "Read data",
  close: "Finish",
  opendir: "Open the folder",
  readdir: "Read the listing",
  stat: "Check the file",
  lstat: "Check the file",
  fstat: "Check the open file",
  setstat: "Change attributes",
  fsetstat: "Change attributes",
  remove: "Delete the file",
  rename: "Rename",
  mkdir: "Make a folder",
  rmdir: "Delete a folder",
  realpath: "Resolve a path",
  statvfs: "Check free space",
};

// steps map each request to the step of a custom fault that acts on it.
const steps = {
  connect: "connect",
  authenticate: "authenticate",
  open_write: "open_write",
  open_read: "open_read",
  write: "write",
  read: "read",
  close: "close",
  opendir: "list",
  readdir: "list",
  stat: "stat",
  lstat: "stat",
  fstat: "stat",
  setstat: "setstat",
  fsetstat: "setstat",
  remove: "remove",
  rename: "rename",
  mkdir: "mkdir",
  rmdir: "rmdir",
};

// describeRequest returns how a request behind a line shows: in plain
// words, by its SFTP name, with its result and tone, and the step a custom
// fault would act on to make it fail, if one can.
export function describeRequest(r) {
  let plain = requests[r.request] ?? r.request;
  if (r.count) {
    plain += `, ${r.count} ${r.count === 1 ? "piece" : "pieces"}, ${formatBytes(r.bytes)}`;
  }
  let result = r.reply === "ok" ? "OK" : r.reply === "eof" ? "End" : plainReason(r.reply);
  if (r.outcome === "fault") {
    result = r.reply === "ok" ? "Changed by a fault" : `Refused: ${plainReason(r.reply)}`;
  }
  return {
    plain,
    tech: [r.request, r.path, r.target ? `→ ${r.target}` : ""].filter(Boolean).join(" "),
    result: result.charAt(0).toUpperCase() + result.slice(1),
    tone: r.outcome === "fault" ? "fault" : r.outcome === "failed" ? "error" : "ok",
    duration: r.duration_ms ? formatDuration(r.duration_ms) : "",
    step: steps[r.request] ?? null,
  };
}
