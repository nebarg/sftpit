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

// formatDuration returns how long something took, given in milliseconds.
export function formatDuration(ms) {
  if (ms < 10) {
    return `${ms.toFixed(1)} ms`;
  }
  if (ms < 1000) {
    return `${Math.round(ms)} ms`;
  }
  if (ms < 60000) {
    return `${(ms / 1000).toFixed(1)} s`;
  }
  const minutes = Math.floor(ms / 60000);
  return `${minutes} min ${Math.round((ms % 60000) / 1000)} s`;
}

// formatClock returns the time of day of an RFC 3339 time, in the
// viewer's time zone, such as "10:42:07".
export function formatClock(time, zone) {
  return new Date(time).toLocaleTimeString("en-GB", { hour12: false, timeZone: zone });
}
