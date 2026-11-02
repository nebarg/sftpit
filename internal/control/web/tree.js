// treeRows returns the files of a listing, each a clean absolute path, as
// the rows of a tree: each directory followed by what it holds,
// directories first, then by name, with each row's depth below the
// shallowest path listed. Sorting the paths alone would not do, since
// "/a-b" sorts between "/a" and "/a/b".
export function treeRows(files) {
  const children = new Map();
  const listed = new Set(files.map((f) => f.path));
  const tops = [];
  for (const f of files) {
    const parent = parentOf(f.path);
    if (f.path !== "/" && listed.has(parent)) {
      if (!children.has(parent)) {
        children.set(parent, []);
      }
      children.get(parent).push(f);
    } else {
      tops.push(f);
    }
  }
  const rows = [];
  const visit = (list, depth) => {
    for (const f of [...list].sort(byKindThenName)) {
      rows.push({ file: f, depth, name: f.path === "/" ? "/" : nameOf(f.path) });
      visit(children.get(f.path) ?? [], depth + 1);
    }
  };
  visit(tops, 0);
  return rows;
}

function byKindThenName(a, b) {
  if ((a.type === "dir") !== (b.type === "dir")) {
    return a.type === "dir" ? -1 : 1;
  }
  return nameOf(a.path) < nameOf(b.path) ? -1 : nameOf(a.path) > nameOf(b.path) ? 1 : 0;
}

function parentOf(path) {
  const i = path.lastIndexOf("/");
  return i <= 0 ? "/" : path.slice(0, i);
}

function nameOf(path) {
  return path.slice(path.lastIndexOf("/") + 1);
}
