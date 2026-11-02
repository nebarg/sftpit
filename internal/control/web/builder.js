// The scenario builder's catalogue of faults, and the rule that a filled-in
// form compiles to: a recipe where one fits, or else a rule in the long
// form. The server checks the rule, and gives it in the long form, before
// anything applies it.

// Where a fault can be scoped, as the API's match fields name them.
export const locations = ["path", "path_prefix", "path_glob", "filename", "filename_glob"];

// The triggers: every match, the first attempts, an occurrence, a share
// drawn at random, or a moment or window of time.
export const triggerLabels = {
  every: "every match",
  attempts: "the first attempts",
  occurrence: "an occurrence",
  probability: "a probability",
  at: "a moment",
  window: "a time window",
};

const longTriggers = ["every", "attempts", "occurrence", "probability", "window"];
const transferTriggers = ["every", "attempts", "probability"];
// Attempts count the opens of a path, so they suit only faults that can act
// on opens.
const requestTriggers = ["every", "occurrence", "probability", "window"];

// The anchors each time trigger counts from: a moment from the run, a
// connection or a transfer's open, and a window from the run or a
// connection.
export const anchors = { at: ["run", "connection", "transfer"], window: ["run", "connection"] };

// The writing operations, which a read-only path refuses.
const writes = ["open_write", "setstat", "remove", "mkdir", "rmdir", "rename"];

// catalogue describes each fault: its label, the settings its form shows,
// the triggers it takes, and the operations it acts on by default, for a
// fault whose operations can be chosen.
export const catalogue = {
  delay: { label: "Delay", settings: ["operations", "when", "duration"], triggers: longTriggers, operations: "any" },
  failure: { label: "Failure", settings: ["operations", "when", "status"], triggers: longTriggers, operations: "any" },
  drop: { label: "Dropped connection", settings: ["operations", "when", "mode"], triggers: [...longTriggers, "at"], operations: "any" },
  freeze: { label: "Frozen connection", settings: ["operations", "when", "max_freeze"], triggers: [...longTriggers, "at"], operations: "any" },
  stall: { label: "Stall", settings: ["operations", "when", "max_stall"], triggers: longTriggers, operations: "any" },
  partial_upload: { label: "Partial upload", settings: ["cutoff", "result", "status", "mode", "max_freeze"], triggers: transferTriggers },
  partial_download: { label: "Partial download", settings: ["cutoff", "result", "status", "mode", "max_freeze"], triggers: transferTriggers },
  corrupt_download: { label: "Download corruption", settings: ["transform", "offset", "length"], triggers: transferTriggers },
  corrupt_upload: { label: "Upload corruption", settings: ["transform", "offset", "length"], triggers: transferTriggers },
  wrong_size: { label: "Wrong size", settings: ["operations", "size_delta"], triggers: requestTriggers, operations: "stat, lstat, fstat, list" },
  random_failures: { label: "Random failures", settings: ["operations", "when", "status"], triggers: ["probability"], operations: "any" },
  read_only: { label: "Read-only path", settings: ["status"], triggers: requestTriggers },
  missing_file: { label: "Missing file", settings: ["operations"], triggers: ["every", "probability"], operations: "" },
};

// compileRule returns the rule that form gives, or throws an Error saying
// what the form lacks. form holds the builder's fields as strings: id,
// fault, user, key_fingerprint, location (one of locations, or ""),
// location_value, operations, trigger, the trigger's attempts, occurrence,
// probability, at, from, until and anchor, and the fault's settings.
export function compileRule(form) {
  const id = form.id.trim();
  if (id === "") {
    throw new Error("Give the rule an ID, such as corrupt-orders.");
  }
  const fault = catalogue[form.fault];
  if (fault === undefined) {
    throw new Error(`There is no fault ${form.fault}.`);
  }
  if (!fault.triggers.includes(form.trigger)) {
    throw new Error(`A ${fault.label.toLowerCase()} cannot fire at ${triggerLabels[form.trigger] ?? form.trigger}.`);
  }
  const scope = scopeOf(form);
  switch (form.fault) {
    case "partial_upload":
    case "partial_download":
      return {
        id,
        [form.fault === "partial_upload" ? "fail_upload" : "fail_download"]: {
          ...scope,
          ...recipeTrigger(form),
          after_bytes: range(form.cutoff, Number),
          ...result(form),
        },
      };
    case "corrupt_download":
    case "corrupt_upload":
      return { id, [form.fault]: { ...scope, ...recipeTrigger(form), ...corruption(form) } };
    case "random_failures":
      return {
        id,
        fail_randomly: { ...scope, operations: list(form.operations || fault.operations), probability: number(form.probability, "probability"), ...given("status", form.status), ...given("when", form.when) },
      };
    case "missing_file":
      return { id, missing_file: { ...scope, ...operations(form, "operations"), ...recipeTrigger(form) } };
  }
  const rule = { id, match: { ...scope, operation: list(ruleOperations(form, fault)) } };
  Object.assign(rule.match, matchTrigger(form));
  const trigger = timeTrigger(form);
  if (trigger) {
    rule.trigger = trigger;
    // At a moment of the run or the connection, a drop or freeze acts on
    // connections, whatever they are doing, so it has no operation.
    if (trigger.at !== undefined && trigger.anchor !== "transfer") {
      if (form.location) {
        throw new Error(`A ${fault.label.toLowerCase()} at a moment of the ${trigger.anchor} acts on whole connections, so scope it only by user or key.`);
      }
      delete rule.match.operation;
    }
  }
  if (form.trigger === "probability") {
    rule.decision = { probability: number(form.probability, "probability") };
  }
  rule.action = action(form, trigger?.at !== undefined);
  return rule;
}

// ruleOperations returns the operations a long-form rule matches: those
// chosen, or the opens if it counts attempts, which count opens, or else
// the fault's own.
function ruleOperations(form, fault) {
  if (form.fault === "read_only") {
    return writes.join(", ");
  }
  return form.operations || (form.trigger === "attempts" ? "open_read, open_write" : fault.operations);
}

function scopeOf(form) {
  const scope = {};
  if (form.user.trim()) {
    scope.user = form.user.trim();
  }
  if (form.key_fingerprint.trim()) {
    scope.key_fingerprint = form.key_fingerprint.trim();
  }
  if (form.location) {
    if (!locations.includes(form.location)) {
      throw new Error(`There is no scope ${form.location}.`);
    }
    if (!form.location_value.trim()) {
      throw new Error("Give the path, prefix, glob or name to scope the fault to.");
    }
    scope[form.location] = form.location_value.trim();
  }
  return scope;
}

// recipeTrigger returns a recipe's attempts or probability.
function recipeTrigger(form) {
  switch (form.trigger) {
    case "attempts":
      return { attempts: firstN(form.attempts) };
    case "probability":
      return { probability: number(form.probability, "probability") };
  }
  return {};
}

// matchTrigger returns the match fields of a rule's attempt or occurrence.
function matchTrigger(form) {
  switch (form.trigger) {
    case "attempts":
      return { attempt: { per: ["user", "path"], numbers: firstN(form.attempts) } };
    case "occurrence":
      return { occurrence: list(form.occurrence).map((n) => number(n, "occurrence")) };
  }
  return {};
}

function timeTrigger(form) {
  if (anchors[form.trigger] && !anchors[form.trigger].includes(form.anchor)) {
    throw new Error(`${triggerLabels[form.trigger]} counts from the ${anchors[form.trigger].join(" or the ")}.`.replace(/^./, (c) => c.toUpperCase()));
  }
  switch (form.trigger) {
    case "at":
      return { at: range(form.at, String), anchor: form.anchor };
    case "window":
      return { window: { from: required(form.from, "the window's start"), until: required(form.until, "the window's end") }, anchor: form.anchor };
  }
  return null;
}

// action returns a rule's action. A drop or freeze at a moment has no when.
function action(form, atMoment) {
  const when = atMoment ? {} : given("when", form.when);
  switch (form.fault) {
    case "delay":
      return { type: "delay", ...when, duration: range(required(form.duration, "the delay"), String) };
    case "failure":
      return { type: "fail", ...when, ...given("status", form.status) };
    case "drop":
      return { type: "close_connection", ...when, ...given("mode", form.mode) };
    case "freeze":
      return { type: "freeze_connection", ...when, ...given("max_freeze", form.max_freeze) };
    case "stall":
      return { type: "stall", ...when, ...given("max_stall", form.max_stall) };
    case "wrong_size":
      return { type: "wrong_size", size_delta: number(form.size_delta, "size change") };
    case "read_only":
      return { type: "fail", when: "before", status: form.status || "permission_denied" };
  }
  throw new Error(`There is no fault ${form.fault}.`);
}

function result(form) {
  switch (form.result) {
    case "close_connection":
      return { result: "close_connection", ...given("mode", form.mode) };
    case "freeze_connection":
      return { result: "freeze_connection", ...given("max_freeze", form.max_freeze) };
  }
  return { result: "status", ...given("status", form.status) };
}

function corruption(form) {
  const c = { transform: form.transform, offset: number(form.offset || "0", "offset") };
  if (form.transform !== "truncate") {
    c.length = number(form.length, "length");
  }
  return c;
}

function operations(form, field) {
  const ops = list(form.operations);
  return ops.length ? { [field]: ops } : {};
}

function given(field, value) {
  return value ? { [field]: value } : {};
}

// firstN returns the attempts 1 to n.
function firstN(n) {
  const count = number(n, "number of attempts");
  if (!Number.isInteger(count) || count < 1) {
    throw new Error("The number of attempts must be a whole number of at least 1.");
  }
  return Array.from({ length: count }, (_, i) => i + 1);
}

// range reads "5" as a value and "1-9" as {min, max}, each converted by
// convert: Number for bytes, String for durations such as "1s-3s".
function range(text, convert) {
  const value = required(text, "a value");
  const parts = value.split(/\s*[-–]\s*/);
  const one = (s) => (convert === Number ? number(s, "value") : s);
  if (parts.length === 2 && parts[0] !== "" && parts[1] !== "") {
    return { min: one(parts[0]), max: one(parts[1]) };
  }
  return one(value);
}

function list(text) {
  return text
    .split(",")
    .map((s) => s.trim())
    .filter((s) => s !== "");
}

function number(text, what) {
  const n = Number(String(text).trim());
  if (String(text).trim() === "" || !Number.isFinite(n)) {
    throw new Error(`The ${what} must be a number.`);
  }
  return n;
}

function required(text, what) {
  const value = (text ?? "").trim();
  if (value === "") {
    throw new Error(`Give ${what}.`);
  }
  return value;
}
