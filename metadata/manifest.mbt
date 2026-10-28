///|
/// Parsed `moon.mod` (TOML-style) module manifest.
pub(all) struct Manifest {
  name : String
  version : String
  repository : String
  readme : String
  deps : Array[String]
} derive(Debug, Eq)

///|
/// Parse a TOML-style `moon.mod`. Returns `None` when no `name = "..."` is found.
pub fn parse_manifest(text : String) -> Manifest? {
  let mut name = ""
  let mut version = ""
  let mut repository = ""
  let mut readme = ""
  let deps : Array[String] = []
  let mut in_import = false
  for line in text.split("\n") {
    let l = line.trim().to_owned()
    if in_import || (l.has_prefix("import") && l.contains("{")) {
      if l.has_prefix("import") && l.contains("{") {
        in_import = !l.contains("}")
      } else if l.contains("}") {
        in_import = false
      }
      for q in quoted_parts(l) {
        deps.push(strip_version(q))
      }
      continue
    }
    // Top-level keys must start at column 0 on the raw line and be followed
    // by `=`/`:`/whitespace: an indented `name:` label inside a `rule(...)`
    // block must not override the module name (real-world case: openseek's
    // `rule(name: "md_to_mbt_string", ...)` was misread as the module name).
    if is_top_key(line.to_owned(), "name") {
      match first_quoted(l) {
        Some(v) => if name == "" { name = v }
        None => ()
      }
    } else if is_top_key(line.to_owned(), "version") {
      match first_quoted(l) {
        Some(v) => if version == "" { version = v }
        None => ()
      }
    } else if is_top_key(line.to_owned(), "repository") {
      match first_quoted(l) {
        Some(v) => if repository == "" { repository = v }
        None => ()
      }
    } else if is_top_key(line.to_owned(), "readme") {
      match first_quoted(l) {
        Some(v) => if readme == "" { readme = v }
        None => ()
      }
    }
  }
  if name == "" {
    None
  } else {
    Some({ name, version, repository, readme, deps, })
  }
}

///|
/// True when `raw` starts at column 0 with `key` immediately followed by an
/// assignment (`=`/`:`) or whitespace, i.e. a genuine top-level TOML key.
fn is_top_key(raw : String, key : String) -> Bool {
  if !raw.has_prefix(key) {
    return false
  }
  let n = raw.length()
  let kl = key.length()
  if n == kl {
    return false
  }
  let c = raw[kl]
  // '=' 61, ':' 58, ' ' 32, '\t' 9
  c == 61 || c == 58 || c == 32 || c == 9
}

///|
/// Parse a legacy `moon.mod.json`. Returns `None` on invalid JSON.
pub fn parse_manifest_json(text : String) -> Manifest? {
  try {
    let j = @json.parse(text)
    Some({
      name: json_field(j, "name"),
      version: json_field(j, "version"),
      repository: json_field(j, "repository"),
      readme: json_field(j, "readme"),
      deps: [],
    })
  } catch {
    _ => None
  }
}

///|
/// Parsed `moon.pkg` (new DSL or legacy JSON) package manifest.
pub(all) struct PkgInfo {
  imports : Array[String]
  pre_build : Array[String]
} derive(Debug)

///|
/// Parse a `moon.pkg` / `moon.pkg.json`; extracts import paths and pre-build
/// command values. JSON input (leading `{`) goes through `@json`.
pub fn parse_pkg(text : String) -> PkgInfo {
  let t = text.trim().to_owned()
  if t.has_prefix("{") {
    return parse_pkg_json(t)
  }
  let imports : Array[String] = []
  let pre_build : Array[String] = []
  let mut in_import = false
  let mut in_prebuild = false
  for line in t.split("\n") {
    let l = line.trim().to_owned()
    if in_import || (l.has_prefix("import") && l.contains("{")) {
      if l.has_prefix("import") && l.contains("{") {
        in_import = !l.contains("}")
      } else if l.contains("}") {
        in_import = false
      }
      for q in quoted_parts(l) {
        imports.push(q)
      }
      continue
    }
    if l.has_prefix("pre-build") && l.contains("(") {
      in_prebuild = !l.contains(")")
      for c in commands_in_line(l) {
        pre_build.push(c)
      }
      continue
    }
    if in_prebuild {
      if l.has_prefix(")") {
        in_prebuild = false
      } else {
        for c in commands_in_line(l) {
          pre_build.push(c)
        }
      }
    }
  }
  { imports, pre_build, }
}

///|
fn parse_pkg_json(text : String) -> PkgInfo {
  let imports : Array[String] = []
  let pre_build : Array[String] = []
  try {
    match @json.parse(text) {
      Object(m) => {
        match m.get("import") {
          Some(Array(items)) =>
            for item in items {
              match item {
                String(s) => imports.push(s)
                _ => ()
              }
            }
          _ => ()
        }
        match m.get("pre-build") {
          Some(Array(items)) =>
            for item in items {
              match item {
                Object(entry) =>
                  match entry.get("command") {
                    Some(String(c)) => pre_build.push(c)
                    _ => ()
                  }
                _ => ()
              }
            }
          _ => ()
        }
      }
      _ => ()
    }
  } catch {
    _ => ()
  }
  { imports, pre_build, }
}

///|
/// All double-quoted substrings on a line, in order (odd segments of a
/// quote-split). `@alias` suffixes and trailing commas fall into even
/// segments and are ignored.
fn quoted_parts(l : String) -> Array[String] {
  let out : Array[String] = []
  for i, part in l.split("\"").collect() {
    if i % 2 == 1 {
      out.push(part.to_owned())
    }
  }
  out
}

///|
fn first_quoted(l : String) -> String? {
  quoted_parts(l).get(0)
}

///|
/// Strip a trailing `@version` from a module path.
fn strip_version(dep : String) -> String {
  match dep.split("@").next() {
    Some(prefix) => prefix.to_owned()
    None => dep
  }
}

///|
/// Values of `"command": "..."` entries on a line: the quoted value
/// immediately following a quoted `command` key.
fn commands_in_line(l : String) -> Array[String] {
  let out : Array[String] = []
  let parts = l.split("\"").collect()
  for i, part in parts {
    if i % 2 == 1 &&
      i + 2 < parts.length() &&
      part.trim().to_owned() == "command" {
      out.push(parts[i + 2].to_owned())
    }
  }
  out
}

///|
fn json_field(j : Json, key : String) -> String {
  match j {
    Object(m) =>
      match m.get(key) {
        Some(String(s)) => s
        _ => ""
      }
    _ => ""
  }
}
