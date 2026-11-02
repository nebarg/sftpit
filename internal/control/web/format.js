// Formatting of the API's values for display. Everything here returns
// plain strings, which the page sets as text, never as HTML.

const units = ["B", "KiB", "MiB", "GiB", "TiB"];

// formatBytes returns n bytes in binary units, such as "1.5 MiB".
export function formatBytes(n) {
  let value = n;
  let unit = 0;
  while (value >= 1024 && unit < units.length - 1) {
    value /= 1024;
    unit++;
  }
  return unit === 0 ? `${n} B` : `${value.toFixed(1)} ${units[unit]}`;
}

// formatElapsed returns a time since the run started, given in
// milliseconds, as minutes, seconds and milliseconds, such as "1:02.345".
export function formatElapsed(ms) {
  const total = Math.max(0, Math.floor(ms));
  const minutes = Math.floor(total / 60000);
  const seconds = Math.floor((total % 60000) / 1000);
  const millis = total % 1000;
  return `${minutes}:${String(seconds).padStart(2, "0")}.${String(millis).padStart(3, "0")}`;
}

// formatDuration returns how long something took, given in milliseconds.
export function formatDuration(ms) {
  if (ms < 10) {
    return `${ms.toFixed(1)} ms`;
  }
  if (ms < 1000) {
    return `${Math.round(ms)} ms`;
  }
  return `${(ms / 1000).toFixed(2)} s`;
}

// shortName drops the SSH_FXP_ or SSH_FX_ prefix of a request or reply.
export function shortName(name) {
  return name ? name.replace(/^SSH_FXP?_/, "") : "";
}

// isFailure reports whether a reply is a status other than OK or EOF.
export function isFailure(reply) {
  return reply !== undefined && reply.startsWith("SSH_FX_") && reply !== "SSH_FX_OK" && reply !== "SSH_FX_EOF";
}

// describeEvent returns how an event shows in the timeline: its tone,
// which is "fault" for what a rule injected, "policy" for what the
// read-only policy refused, "error" for a failure that sftpit did not
// inject, "notice" for the run's own changes and "" otherwise, and a
// one-line summary.
export function describeEvent(e) {
  switch (e.kind) {
    case "run_started":
      return { tone: "notice", summary: `Run started: ${scenarioName(e.run)}, seed ${e.run.seed}${e.run.seed_pinned ? " (pinned)" : ""}` };
    case "connected":
      return { tone: "", summary: `Connection ${e.connection} opened` };
    case "authenticated":
      return { tone: "", summary: `Logged in as ${e.user}${e.key_fingerprint ? ` with key ${e.key_fingerprint}` : ""}` };
    case "disconnected":
      return { tone: "", summary: `Connection ${e.connection} closed${e.reason ? `: ${e.reason}` : ""}` };
    case "operation":
      return describeOperation(e);
    case "transfer":
      return { tone: e.transfer.faulted ? "fault" : "", summary: describeTransfer(e) };
    case "fault":
      return { tone: "fault", summary: `Injected ${describeFault(e.fault)} on ${target(e)}` };
    case "fault_ended":
      return { tone: "fault", summary: `${e.fault.type} ended: ${e.reason}` };
    case "suppressed":
      return { tone: "", summary: `Suppressed a fault of ${e.rule}: ${e.reason}` };
    case "decision":
      return { tone: "", summary: `${e.rule} ${describeDecision(e.decision)}` };
    case "rules_changed":
      return { tone: "notice", summary: `Rules changed to revision ${e.rules.revision}` };
    case "snapshot":
      return { tone: "notice", summary: `Kept ${e.snapshot.copy ? "a copy" : "a record"} of ${e.path}, ${formatBytes(e.snapshot.size)}` };
  }
  return { tone: "", summary: e.kind };
}

function scenarioName(run) {
  if (run.inline) {
    return "an inline scenario";
  }
  return run.scenario ? `scenario ${run.scenario}` : "no scenario";
}

function describeOperation(e) {
  const reply = e.backend_reply && e.backend_reply !== e.reply ? `${shortName(e.reply)} (backend: ${shortName(e.backend_reply)})` : shortName(e.reply);
  const summary = `${shortName(e.request)} ${target(e)} → ${reply}`;
  if (e.rule) {
    return { tone: "fault", summary };
  }
  if (e.read_only) {
    return { tone: "policy", summary: `${summary}, read-only ${e.read_only}` };
  }
  return { tone: isFailure(e.reply) ? "error" : "", summary };
}

function describeTransfer(e) {
  const t = e.transfer;
  const parts = [];
  if (t.reads) {
    parts.push(`${t.reads} reads, ${formatBytes(t.bytes_read)}`);
  }
  if (t.writes) {
    parts.push(`${t.writes} writes, ${formatBytes(t.bytes_written)}`);
  }
  if (parts.length === 0) {
    parts.push("nothing read or written");
  }
  return `Transfer of ${e.path} (${t.mode}): ${parts.join(", ")}, closed by ${t.closed}`;
}

function describeFault(f) {
  return f.when ? `${f.type} (${f.when})` : f.type;
}

function describeDecision(d) {
  if (d.fired !== undefined) {
    return `drew ${d.draw.toFixed(4)} against ${d.probability}: ${d.fired ? "fires" : "does not fire"}`;
  }
  return `drew ${d.draw.toFixed(4)}: ${d.choice} ${d.value}`;
}

function target(e) {
  const what = e.request ? shortName(e.request) : "";
  if (e.path && e.target) {
    return `${e.path} → ${e.target}`;
  }
  return e.path || what || `connection ${e.connection}`;
}
