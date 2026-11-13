// Number fields accept only what makes a number of their kind.

// cleanNumber returns value with every character that a number of kind,
// "integer" or "decimal", cannot hold removed: anything but digits, and for
// a decimal, any point after the first. caret is a position in value, and
// the position it moves to is returned with the cleaned value.
export function cleanNumber(value, kind, caret = value.length) {
  let cleaned = "";
  let at = 0;
  let point = false;
  for (let i = 0; i < value.length; i++) {
    const c = value[i];
    const keep = (c >= "0" && c <= "9") || (c === "." && kind === "decimal" && !point);
    if (keep) {
      point ||= c === ".";
      cleaned += c;
    }
    if (keep && i < caret) {
      at++;
    }
  }
  return { value: cleaned, caret: at };
}

// keepNumbers cleans every field marked data-number, with its kind, as it
// is typed in or pasted into, inside root.
export function keepNumbers(root) {
  root.addEventListener(
    "input",
    (event) => {
      const field = event.target;
      const kind = field.dataset?.number;
      if (!kind) {
        return;
      }
      const { value, caret } = cleanNumber(field.value, kind, field.selectionStart ?? field.value.length);
      if (value !== field.value) {
        field.value = value;
        field.setSelectionRange(caret, caret);
      }
    },
    // Cleaned before any other listener reads the field.
    { capture: true },
  );
}
