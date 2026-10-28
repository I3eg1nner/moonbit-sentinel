///|
pub(all) struct ScanOptions {
  /// 注册表权威模块名（来自 mooncakes.io 索引；直扫本地目录时为 ""）。
  /// 仅用于报告标识，不参与判定。
  authoritative_name : String
} derive(Debug)

///|
fn basename(p : String) -> String {
  match p.rev_find("/") {
    Some(i) => p[i + 1:].to_owned()
    None => p
  }
}

///|
fn rel(base : String, p : String) -> String {
  if p.length() > base.length() {
    p[base.length() + 1:].to_owned()
  } else {
    p
  }
}

///|
async fn walk_files(dir : String, acc : Array[String]) -> Unit {
  for name in @fs.readdir(dir) {
    let p = dir + "/" + name
    match @fs.kind(p, follow_symlink=false) {
      SymLink => ()
      Directory => walk_files(p, acc)
      _ => acc.push(p)
    }
  }
}

///|
/// 读取文件内容用于 S10 魔数与内嵌字符串探测；超过 2MB 的文件视为资产（模型/字体）跳过
async fn read_artifact_opt(path : String) -> Bytes? {
  try {
    let bytes = @fs.read_file(path).binary()
    guard bytes.length() <= 2 * 1024 * 1024 else { return None }
    Some(bytes)
  } catch {
    _ => None
  }
}

///|
async fn read_opt(path : String) -> String? {
  Some(@fs.read_file(path).text()) catch {
    _ => None
  }
}

///|
pub async fn run_scan(root : String, opts : ScanOptions) -> @report.Report {
  let errors : Array[String] = []
  let findings : Array[@engine.Finding] = []
  // manifest
  let mtext = match read_opt(root + "/moon.mod") {
    Some(t) => t
    None => ""
  }
  let manifest = match @metadata.parse_manifest(mtext) {
    Some(m) => Some(m)
    None =>
      match @metadata.parse_manifest_json(mtext) {
        Some(m) => Some(m)
        None => {
          let jtext = match read_opt(root + "/moon.mod.json") {
            Some(t) => t
            None => ""
          }
          match @metadata.parse_manifest_json(jtext) {
            Some(m) => Some(m)
            None => {
              errors.push("cannot parse moon.mod")
              None
            }
          }
        }
      }
  }
  let module_name = match manifest {
    Some(m) => m.name
    None => basename(root)
  }
  let version = match manifest {
    Some(m) => m.version
    None => ""
  }
  // walk all files under root
  let files : Array[String] = []
  walk_files(root, files)
  // pkg files → S06; source files → all source rules
  let rules = @source.all_source_rules()
  for p in files {
    let name = basename(p)
    let relp = rel(root, p)
    if name is "moon.pkg" || name is "moon.pkg.json" {
      match read_opt(p) {
        Some(t) =>
          for f in @metadata.s06(@metadata.parse_pkg(t), relp) {
            findings.push(f)
          }
        None => ()
      }
    } else if @source.is_source_file(name) {
      match read_opt(p) {
        Some(content) => {
          let scanned = if name.has_suffix(".mbt.md") {
            @source.extract_fenced_code(content)
          } else {
            content
          }
          let scanned = @source.strip_line_comments(scanned)
          let ctx : @source.SourceCtx = {
            file: relp,
            content: scanned,
            lines: @matchers.LineIndex::build(scanned),
          }
          let test_file = @source.is_nonproduction_file(relp)
          for rule in rules {
            let (_, rulefn) = rule
            for f in rulefn(ctx) {
              if test_file {
                findings.push({ ..f, severity: @source.downgrade(f.severity), })
              } else {
                findings.push(f)
              }
            }
          }
          // 解码载荷检查只在生产文件执行（测试夹具常有编码样本）
          if !test_file {
            for f in @source.s04_payload(ctx) {
              findings.push(f)
            }
          }
        }
        None => errors.push("cannot read \{relp}")
      }
    } else {
      // S10：源码/清单之外的文件做落地产物检查（二进制魔数/嵌套压缩包/脚本）
      match read_artifact_opt(p) {
        Some(head) =>
          for
            f in @source.s10_artifact(
              relp,
              head,
              @source.is_nested_archive(name),
              @source.is_script_file(name),
            ) {
            findings.push(f)
          }
        None => ()
      }
    }
  }
  let combined = @source.combine_rules(findings)
  let risk = @score.risk_of(combined)
  {
    module: module_name,
    version,
    risk,
    verdict: @score.verdict_of(risk).to_string(),
    findings: combined,
    errors,
  }
}
