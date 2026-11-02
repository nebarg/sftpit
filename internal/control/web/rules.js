// Summaries of a run's rules, in the long form that the rules route gives
// them, for the rules table.

const locations = [
  ["path", ""],
  ["path_prefix", "under "],
  ["path_glob", ""],
  ["filename", "named "],
  ["filename_glob", "named "],
  ["source", "from "],
  ["source_prefix", "from under "],
  ["source_glob", "from "],
  ["source_filename", "from one named "],
  ["source_filename_glob", "from one named "],
  ["target", "to "],
  ["target_prefix", "to under "],
  ["target_glob", "to "],
  ["target_filename", "to one named "],
  ["target_filename_glob", "to one named "],
];

// describeMatch says what a rule matches, such as
// "write under /in, user test, attempt 1 per user and path".
export function describeMatch(rule) {
  const m = rule.match ?? {};
  const parts = [m.operation?.length ? m.operation.join(", ") : "any operation"];
  for (const [field, prefix] of locations) {
    if (m[field]) {
      parts.push(prefix + m[field]);
    }
  }
  if (m.user) {
    parts.push(`user ${m.user}`);
  }
  if (m.key_fingerprint) {
    parts.push(`key ${m.key_fingerprint}`);
  }
  if (m.attempt) {
    const per = m.attempt.per?.length ? ` per ${m.attempt.per.join(" and ")}` : "";
    parts.push(`attempt ${m.attempt.numbers.join(", ")}${per}`);
  }
  if (m.occurrence?.length) {
    parts.push(`occurrence ${m.occurrence.join(", ")}`);
  }
  const t = rule.trigger;
  if (t?.at !== undefined) {
    parts.push(`at ${range(t.at)} into the ${t.anchor}`);
  } else if (t?.window) {
    parts.push(`from ${t.window.from} to ${t.window.until} into the ${t.anchor}`);
  }
  if (rule.decision) {
    parts.push(`with probability ${rule.decision.probability} per ${rule.decision.scope}`);
  }
  if (rule.max_triggers) {
    parts.push(`at most ${rule.max_triggers} times`);
  }
  return parts.join(", ");
}

// describeAction says what a rule does, such as
// "partial_upload, cutoff_offset 5, result status, status failure".
export function describeAction(rule) {
  const a = rule.action;
  const parts = [a.type];
  for (const [field, value] of Object.entries(a)) {
    if (field !== "type") {
      parts.push(`${field} ${range(value)}`);
    }
  }
  return parts.join(", ");
}

// ruleRows returns a row for each of a run's rules, in the order they are
// tried, then for each rule that chaos compiles to, with what each has
// done and whether it has never matched, which a shadowed or mistyped
// rule shows.
export function ruleRows(reply) {
  const counts = reply.counts ?? {};
  const zero = { matched: 0, selected: 0, fired: 0, canceled: 0 };
  const rows = reply.faults.map((rule) => ({
    id: rule.id,
    priority: rule.priority,
    match: describeMatch(rule),
    action: describeAction(rule),
    counts: counts[rule.id] ?? zero,
    chaos: false,
  }));
  const own = new Set(reply.faults.map((r) => r.id));
  for (const id of Object.keys(counts).sort()) {
    if (!own.has(id)) {
      rows.push({ id, priority: null, match: "chaos", action: "", counts: counts[id], chaos: true });
    }
  }
  for (const row of rows) {
    row.neverMatched = row.counts.matched === 0;
  }
  return rows;
}

// describeChaos says what a run's chaos is, such as
// "moderate chaos for user test, paused".
export function describeChaos(chaos) {
  const scope = Object.entries(chaos.scope ?? {}).map(([k, v]) => `${k.replaceAll("_", " ")} ${v}`);
  const extras = chaos.extras?.length ? ` with ${chaos.extras.join(" and ")}` : "";
  return `${chaos.preset} chaos${extras} for ${scope.length ? scope.join(", ") : "everyone"}${chaos.paused ? ", paused" : ""}`;
}

function range(v) {
  if (v !== null && typeof v === "object" && "min" in v) {
    return `${v.min}–${v.max}`;
  }
  return String(v);
}
