// Scenarios in plain words: how each one reads, the names a scenario can
// have, and the body that saves the faults that are on as a scenario.

const sources = { built_in: "Built in", config: "From the config file", file: "Saved" };

// describeScenario returns how a scenario the API gives shows: its name,
// description, where it is defined and how many faults it has, or why its
// file holds no scenario, and whether it can be deleted.
export function describeScenario(s) {
  const source = sources[s.source] ?? s.source;
  const faults = s.faults.length === 1 ? "1 fault" : `${s.faults.length} faults`;
  return {
    name: s.name,
    description: s.description ?? "",
    about: s.error ? source : `${source} · ${faults}`,
    error: s.error ?? "",
    deletable: s.source === "file",
  };
}

// cleanScenarioName returns value with only what a scenario name can hold:
// lowercase letters, digits and -, starting with a letter or digit. Capitals
// are lowered, and spaces and _ become -. caret is a position in value, and
// the position it moves to is returned with the cleaned value.
export function cleanScenarioName(value, caret = value.length) {
  let cleaned = "";
  let at = 0;
  for (let i = 0; i < value.length; i++) {
    let c = value[i].toLowerCase();
    if (c === " " || c === "_") {
      c = "-";
    }
    const keep = (c >= "a" && c <= "z") || (c >= "0" && c <= "9") || (c === "-" && cleaned !== "");
    if (keep) {
      cleaned += c;
    }
    if (keep && i < caret) {
      at++;
    }
  }
  return { value: cleaned, caret: at };
}

// scenarioBody returns the body of PUT /api/scenarios/{name} that saves the
// faults that are on, as GET /api/faults lists them, with a description if
// one is given. It throws an Error if no fault is on.
export function scenarioBody(faults, description) {
  const on = faults.filter((f) => f.on).map(({ id, on, happened, scenario, ...fault }) => fault);
  if (on.length === 0) {
    throw new Error("Turn on at least one fault to save it as a scenario.");
  }
  const body = { faults: on };
  if (description.trim() !== "") {
    body.description = description.trim();
  }
  return body;
}
