// The events the timeline shows, newest first, bounded so that a long run
// cannot exhaust the browser's memory.

// Timeline holds up to limit entries: events, and gaps where events that
// were asked for are gone.
export class Timeline {
  constructor(limit) {
    this.limit = limit;
    this.entries = [];
    this.lastId = 0;
    // dropped counts the entries let go to stay within the limit.
    this.dropped = 0;
  }

  // add adds an event, and reports whether it was new: an event the stream
  // sends again after a reconnection is not.
  add(event) {
    if (event.id <= this.lastId) {
      return false;
    }
    this.lastId = event.id;
    this.push({ event });
    return true;
  }

  // gap records that the events after the ID after and before firstId are
  // gone.
  gap(after, firstId) {
    this.push({ gap: { after, firstId } });
  }

  push(entry) {
    this.entries.unshift(entry);
    if (this.entries.length > this.limit) {
      this.dropped += this.entries.length - this.limit;
      this.entries.length = this.limit;
    }
  }
}

// eventQuery returns the query of a request for events that filters
// match, as the events route reads it, leaving out the filters not set.
export function eventQuery(filters) {
  const q = new URLSearchParams();
  for (const name of ["kind", "user", "path", "connection", "rule"]) {
    const value = (filters[name] ?? "").trim();
    if (value !== "") {
      q.set(name, value);
    }
  }
  return q.toString();
}
