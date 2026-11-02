// Calls to the control API, from the same origin.

// APIError is a reply other than 2xx, with the API's error message.
export class APIError extends Error {
  constructor(status, message) {
    super(message);
    this.status = status;
  }
}

// get returns the JSON reply to a GET of path.
export async function get(path) {
  return reply(await fetch(path, { headers: { Accept: "application/json" } }));
}

// send makes a change with method, which the API accepts only with its
// Sftpit-Control header, and returns the JSON reply.
export async function send(method, path, body) {
  return reply(
    await fetch(path, {
      method,
      headers: { "Content-Type": "application/json", "Sftpit-Control": "1" },
      body: body === undefined ? undefined : JSON.stringify(body),
    }),
  );
}

async function reply(resp) {
  const body = await resp.json().catch(() => ({}));
  if (!resp.ok) {
    throw new APIError(resp.status, body.error ?? `${resp.status} ${resp.statusText}`);
  }
  return body;
}

// runPath returns the path of a run's route.
export function runPath(run, route) {
  return `/api/v1/runs/${encodeURIComponent(run)}/${route}`;
}
