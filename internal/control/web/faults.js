// Faults in plain words: how each of the run's faults reads, the one
// setting a preset asks for, and the body that the add and custom forms
// send to POST /api/faults.

import { plainReason } from "./activity.js";

// describeFault returns how a fault the API gives shows: its name, a
// summary of what it does, where and how often, and its status.
export function describeFault(f) {
  const summary = [settingOf(f), whereOf(f), oftenOf(f)].filter(Boolean).join(" · ");
  let status = "Off";
  if (f.on) {
    status = f.happened === 0 ? "Not happened yet" : `Happened ${times(f.happened)}`;
  }
  return { name: f.name, summary, status, active: f.on && f.happened > 0 };
}

function times(n) {
  return n === 1 ? "once" : `${n} times`;
}

function settingOf(f) {
  switch (f.do) {
    case "refuse":
      return `refused with “${plainReason(f.error)}”`;
    case "wait":
      return `${f.seconds} s slower`;
    case "hold":
      return "held until released";
    case "freeze":
      return `frozen for up to ${f.seconds} s`;
    case "stop_partway":
      return f.error ? `stops after ${f.kb} KB with “${plainReason(f.error)}”` : `stops after ${f.kb} KB`;
    case "truncate":
      return `cut short after ${f.kb} KB`;
    case "down":
      return `down for ${f.seconds} s`;
  }
  return "";
}

function whereOf(f) {
  let where = "any file";
  if (f.folder) {
    where = `in ${f.folder}`;
  } else if (f.file) {
    where = f.file;
  } else if (f.names) {
    where = `names like ${f.names}`;
  } else if (!f.steps || f.steps.length === 0) {
    where = "the whole server";
  } else if (f.steps.includes("connect") || f.steps.includes("authenticate")) {
    where = "every connection";
  }
  return f.user ? `${where}, for ${f.user}` : where;
}

function oftenOf(f) {
  if (f.first !== undefined) {
    return f.first === 1 ? "first time only" : `first ${f.first} times`;
  }
  if (f.only !== undefined) {
    return `only time number ${f.only}`;
  }
  if (f.percent !== undefined) {
    return `${f.percent}% of the time`;
  }
  if (f.minutes !== undefined) {
    return `for ${f.minutes} ${f.minutes === 1 ? "minute" : "minutes"}`;
  }
  return "every time";
}

// presetSetting returns the one setting a preset asks for, its field, label
// and default, or null if it asks for none.
export function presetSetting(preset) {
  const f = preset.fault;
  if (f.kb !== undefined) {
    return { field: "kb", label: "Stop after (KB)", value: String(f.kb) };
  }
  if (f.seconds !== undefined) {
    return { field: "seconds", label: f.do === "down" ? "Down for (seconds)" : "Extra seconds", value: String(f.seconds) };
  }
  return null;
}

// faultBody returns the body of POST /api/faults for a form's fields, all
// strings: preset, or steps (a list), do, error (of a refusal, or of a
// transfer stopped partway), seconds, kb and after for a custom fault; where ("any", "folder", "file" or "names") and place;
// user; often ("every", "first", "only", "percent" or "minutes") and
// count. It throws an Error saying what a field lacks.
export function faultBody(form) {
  const body = {};
  if (form.preset) {
    body.preset = form.preset;
  } else {
    if (!form.steps || form.steps.length === 0) {
      throw new Error("Choose at least one step.");
    }
    body.steps = form.steps;
    body.do = form.do;
    if ((form.do === "refuse" || form.do === "stop_partway") && form.error) {
      body.error = form.error;
    }
    if (form.after) {
      body.after = true;
    }
  }
  for (const field of ["seconds", "kb"]) {
    if (form[field] !== undefined && form[field] !== "") {
      body[field] = number(form[field], field === "kb" ? "The KB" : "The seconds");
    }
  }
  if (form.where && form.where !== "any") {
    const place = (form.place ?? "").trim();
    if (place === "") {
      throw new Error(`Give the ${form.where === "names" ? "name pattern" : form.where}, or choose any file.`);
    }
    body[form.where] = place;
  }
  if (form.user) {
    body.user = form.user;
  }
  if (form.often && form.often !== "every") {
    body[form.often] = number(form.count, "How often");
  }
  return body;
}

function number(value, what) {
  const n = Number(value);
  if (String(value).trim() === "" || !Number.isFinite(n)) {
    throw new Error(`${what} must be a number.`);
  }
  return n;
}

// summarise returns a custom fault's body as a sentence, naming its steps
// as steps, the catalogue GET /api/presets gives, names them.
export function summarise(body, steps) {
  const names = (body.steps ?? []).map((id) => steps.find((s) => s.id === id)?.name.toLowerCase() ?? id);
  const doing = names.length > 0 ? names.join(" or ") : "doing anything";
  const what = {
    refuse: `refuse with “${plainReason(body.error ?? "failure")}”`,
    wait: `wait ${body.seconds ?? 3} s`,
    hold: "hold it until released",
    drop: "drop the connection",
    freeze: "freeze the connection",
    stop_partway: body.error ? `stop after ${body.kb ?? 32} KB, answering “${plainReason(body.error)}”` : `stop after ${body.kb ?? 32} KB, closing the connection`,
    corrupt: "corrupt the data",
    truncate: `cut the file short after ${body.kb ?? 32} KB, without an error`,
    wrong_size: "report the wrong size",
    hide: "answer “no such file”",
    down: `take the server offline for ${body.seconds ?? 30} s`,
  }[body.do];
  const where = whereOf({ ...body, steps: body.steps ?? ["remove"] });
  // Only these act before or after the server carries out the request; the
  // others change what a transfer or an answer holds.
  const timed = ["refuse", "wait", "hold", "drop", "freeze", "down"].includes(body.do);
  const when = body.after ? "after the server carries out the request" : "before the server carries out the request";
  return `When the client is ${doing} (${where}), ${[what, timed && when, oftenOf(body)].filter(Boolean).join(", ")}.`;
}
