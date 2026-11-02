// el makes an element with the attributes and listeners in props, and
// children. A string child becomes a text node, so nothing the API returns
// is ever parsed as HTML.
export function el(tag, props = {}, ...children) {
  const node = document.createElement(tag);
  for (const [name, value] of Object.entries(props)) {
    if (value === undefined || value === null || value === false) {
      continue;
    }
    if (name.startsWith("on")) {
      node.addEventListener(name.slice(2), value);
    } else {
      node.setAttribute(name, value === true ? "" : String(value));
    }
  }
  node.append(...children.flat().filter((c) => c !== undefined && c !== null && c !== false));
  return node;
}

// show replaces the children of node.
export function show(node, ...children) {
  node.replaceChildren(...children.flat().filter((c) => c !== undefined && c !== null && c !== false));
}
