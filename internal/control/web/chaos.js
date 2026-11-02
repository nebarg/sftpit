// The chaos switch's form, and the chaos it gives, as a change of rules
// takes it.

// The scopes the switch offers: everyone, or one user, path prefix or
// filename.
export const chaosScopes = { "": "everyone", user: "a user", path_prefix: "a path prefix", filename: "a filename" };

// chaosOf returns the chaos that form gives, or null for none. form holds
// the switch's fields: mode, "off", "on" or "paused", preset, scope, one of
// chaosScopes, scope_value and extras, a list.
export function chaosOf(form) {
  if (form.mode === "off") {
    return null;
  }
  const scope = {};
  if (form.scope) {
    const value = form.scope_value.trim();
    if (value === "") {
      throw new Error(`Give ${chaosScopes[form.scope]} to scope chaos to.`);
    }
    scope[form.scope] = value;
  }
  return { preset: form.preset, scope, extras: [...form.extras], paused: form.mode === "paused" };
}

// formOf returns the switch's fields for chaos, a run's chaos as the rules
// route gives it, or null. A scope the switch does not offer, which a
// configuration can give, is kept as it is, with its own name.
export function formOf(chaos) {
  if (!chaos) {
    return { mode: "off", preset: "light", scope: "", scope_value: "", extras: [] };
  }
  const [scope = "", value = ""] = Object.entries(chaos.scope ?? {})[0] ?? [];
  return { mode: chaos.paused ? "paused" : "on", preset: chaos.preset, scope, scope_value: value, extras: chaos.extras ?? [] };
}
