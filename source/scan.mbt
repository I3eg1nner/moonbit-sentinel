///|
/// 测试辅助：以默认文件名构造 SourceCtx
pub fn mkctx_for_test(content : String) -> SourceCtx {
  { file: "src/x.mbt", content, lines: @matchers.LineIndex::build(content), }
}

///|
/// 待审计源码文件分类：.mbt / .mbtx / .mbt.md（排除 moon.pkg、moon.mod 等）
pub fn is_source_file(name : String) -> Bool {
  name.has_suffix(".mbt") ||
  name.has_suffix(".mbtx") ||
  name.has_suffix(".mbt.md")
}

///|
/// 测试文件：其 S 规则命中在扫描层统一降一级严重度，且不参与 S99 组合升级
/// （真实误报：测试夹具同时含 raw-IP 字符串与凭据字样，触发 S99 Critical）。
pub fn is_test_file(name : String) -> Bool {
  name.has_suffix("_test.mbt") ||
  name.has_suffix("_wbtest.mbt") ||
  name.has_suffix("_test.mbt.md")
}

///|
/// 行注释剥离：行首（忽略缩进）为 `//` 的行替换为空行，行数不变以保持行号。
/// 降低注释文字触发的 S02/S03 误报（真实误报：注释里的 "credentials" 字样）。
/// 保守起见不处理块注释与行尾注释。
pub fn strip_line_comments(content : String) -> String {
  let lines : Array[String] = []
  for line in content.split("\n") {
    if line.trim(chars=" \t").has_prefix("//") {
      lines.push("")
    } else {
      lines.push(line.to_owned())
    }
  }
  lines.join("\n")
}

///|
/// 严重度降一级（pub 供扫描层对测试文件降噪复用）
pub fn downgrade(s : @engine.Severity) -> @engine.Severity {
  match s {
    Critical => High
    High => Medium
    Medium => Low
    Low => Low
  }
}

///|
/// `.mbt.md` 文档：围栏代码块（``` 起止）之外的行替换为空行，行数不变以
/// 保持 LineIndex 行号与原文一致；S 规则只扫描过滤后的围栏内容。
pub fn extract_fenced_code(content : String) -> String {
  let lines : Array[String] = []
  let mut in_fence = false
  for line in content.split("\n") {
    if line.trim(chars=" \t").has_prefix("```") {
      in_fence = !in_fence
      lines.push("")
    } else if in_fence {
      lines.push(line.to_owned())
    } else {
      lines.push("")
    }
  }
  lines.join("\n")
}

///|
/// 组合升级：同文件 S01（网络）与 S02/S04（凭据/混淆）同现 → 追加一条 S99 Critical。
/// 双方 feeder 均需 High 及以上（S01 raw-IP、S02 凭据读取、S04 混淆），
/// Low+Low（http client 用法 + 注释中的凭据词）组合不足以升级。
pub fn combine_rules(fs : Array[@engine.Finding]) -> Array[@engine.Finding] {
  let out = fs.copy()
  let has_high = (rule : String, file : String) => {
    fs
    .iter()
    .any(f => {
      f.rule == rule &&
      f.file == file &&
      f.severity.rank() >= @engine.High.rank()
    })
  }
  let files : Array[String] = []
  for f in fs {
    // 测试文件不参与组合升级：夹具同时含 raw-IP 与凭据字样属常态
    if is_test_file(f.file) {
      continue
    }
    if !files.iter().any(x => x == f.file) {
      files.push(f.file)
    }
  }
  for file in files {
    if has_high("S01", file) && (has_high("S02", file) || has_high("S04", file)) {
      let rd : @engine.RuleDef = {
        id: "S99",
        severity: @engine.Critical,
        category: @engine.Source,
        description: "exfil combo",
      }
      out.push(
        rd.finding(
          file~,
          line=1,
          snippet="",
          message="S01 network + credential/obfuscation in same file",
        ),
      )
    }
  }
  out
}

///|
/// 测试辅助：按 is_b64 提取游程
pub fn extract_runs_for_test(s : String, min_len : Int) -> Array[(Int, Int)] {
  extract_runs(s, @matchers.is_b64, min_len)
}
