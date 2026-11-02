// A preview of the start of a file, as text if it reads as text, or else
// as a hex dump. The page shows either as text, never as markup.

// previewBytes is how much of a file a preview reads.
export const previewBytes = 4096;

// preview returns the preview of bytes, the start of a file of size total:
// its kind, "empty", "text" or "hex", its text, and whether the file holds
// more than bytes.
export function preview(bytes, total) {
  const truncated = total > bytes.length;
  if (bytes.length === 0) {
    return { kind: "empty", text: "", truncated };
  }
  const text = asText(bytes, truncated);
  if (text !== null) {
    return { kind: "text", text, truncated };
  }
  return { kind: "hex", text: hexDump(bytes), truncated };
}

// asText returns bytes as text if they are UTF-8 without control
// characters other than tab, newline and carriage return, or null. Up to
// three bytes at the end of a truncated preview may be part of a character
// cut off.
function asText(bytes, truncated) {
  const cuts = truncated ? [0, 1, 2, 3] : [0];
  for (const cut of cuts) {
    if (cut >= bytes.length) {
      break;
    }
    let text;
    try {
      text = new TextDecoder("utf-8", { fatal: true }).decode(bytes.subarray(0, bytes.length - cut));
    } catch {
      continue;
    }
    return /[\u0000-\u0008\u000b\u000c\u000e-\u001f\u007f]/.test(text) ? null : text;
  }
  return null;
}

// hexDump returns bytes as lines of an offset, sixteen bytes in hex and
// the same bytes as printable ASCII, with a dot for any other.
export function hexDump(bytes) {
  const lines = [];
  for (let offset = 0; offset < bytes.length; offset += 16) {
    const row = bytes.subarray(offset, offset + 16);
    const hex = Array.from(row, (b) => b.toString(16).padStart(2, "0")).join(" ");
    const ascii = Array.from(row, (b) => (b >= 0x20 && b < 0x7f ? String.fromCharCode(b) : ".")).join("");
    lines.push(`${offset.toString(16).padStart(8, "0")}  ${hex.padEnd(47)}  |${ascii}|`);
  }
  return lines.join("\n");
}
