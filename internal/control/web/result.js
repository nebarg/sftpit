// The verdict on a run, for the result view: what its assertions say in a
// line, and how the rules that the report lists turned out.

// describeCount says what a count allows, from an assertion as a scenario
// gives it, which has at least 1 if it gives no bound.
function describeCount(a) {
  if (a.exactly !== undefined) {
    return `exactly ${a.exactly}`;
  }
  if (a.at_least !== undefined && a.at_most !== undefined) {
    return `${a.at_least} to ${a.at_most}`;
  }
  return a.at_most !== undefined ? `at most ${a.at_most}` : `at least ${a.at_least ?? 1}`;
}

// describeAssertion says what an assertion checks in a line, as a report's
// description does.
export function describeAssertion(a) {
  switch (a.type) {
    case "rule_fired":
      return `rule_fired ${a.rule_id}, ${describeCount(a)}`;
    case "successful_operation": {
      if (a.operation !== "rename") {
        return `successful_operation ${a.operation} ${a.path}, ${describeCount(a)}`;
      }
      const renamed = a.source && a.target ? `${a.source} to ${a.target}` : a.source ? `from ${a.source}` : `to ${a.target}`;
      return `successful_operation rename ${renamed}, ${describeCount(a)}`;
    }
    case "file_equals_fixture":
      return `file_equals_fixture ${a.path}, fixture ${a.fixture}`;
    case "file_hash":
      return `file_hash ${a.path}, sha256 ${a.sha256}`;
  }
  return `${a.type} ${a.path}`;
}

// ruleOutcomes lists the rules of a report, those that never fired first,
// by ID, each with what it came to.
export function ruleOutcomes(rules) {
  return Object.entries(rules)
    .map(([id, counts]) => ({ id, ...counts, outcome: counts.fired > 0 ? "fired" : counts.matched > 0 ? "matched, never fired" : "never matched" }))
    .sort((a, b) => Number(a.fired > 0) - Number(b.fired > 0) || (a.id < b.id ? -1 : 1));
}

// checkWarning says what checking a run does, for the person about to.
export function checkWarning(timeout) {
  return `Checking ends this run. Admission closes, clients have ${timeout} to close their files, every connection ends, and the run admits no clients until a reset. Check it?`;
}
