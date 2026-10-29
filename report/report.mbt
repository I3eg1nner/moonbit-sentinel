///|
pub(all) struct Report {
  module : String
  version : String
  risk : Int32
  verdict : String
  findings : Array[@engine.Finding]
  errors : Array[String]
} derive(Debug, ToJson)

///|
pub fn Report::to_json_string(self : Report) -> String {
  self.to_json().stringify()
}

///|
pub fn human_summary(r : Report) -> String {
  let sb = StringBuilder()
  sb <+ "module: \{r.module}@\{r.version}\n"
  sb <+ "risk: \{r.risk} verdict: \{r.verdict}\n"
  sb <+ "findings: \{r.findings.length()} errors: \{r.errors.length()}\n"
  for f in r.findings {
    sb <+
      "  [\{f.rule}/\{f.severity.label()}] \{f.file}:\{f.line} \{f.message}\n"
  }
  sb.to_string()
}

///|
/// Markdown 摘要（GitHub step summary / PR 评论用）：
/// verdict 徽标 + 风险分 + 按严重度分组的 findings 表
pub fn summary_md(r : Report) -> String {
  let badge = match r.verdict {
    "Malicious" => "🔴"
    "Suspicious" => "🟡"
    "Clean" => "🟢"
    _ => "⚪"
  }
  let sb = StringBuilder()
  sb <+ "## \{badge} mooncake-audit: \{r.verdict}\n\n"
  sb <+ "- module: `\{r.module}`@\{r.version}\n"
  sb <+ "- risk: **\{r.risk}** (\{r.findings.length()} findings)\n\n"
  let order : Array[@engine.Severity] = [Critical, High, Medium, Low]
  for sev in order {
    let group = r.findings.filter(f => f.severity == sev)
    if group.length() == 0 {
      continue
    }
    sb <+ "### \{sev_name_md(sev)} (\{group.length()})\n\n"
    sb <+ "| rule | location | detail |\n|---|---|---|\n"
    for f in group {
      let loc = if f.file is "" { "-" } else { "`\{f.file}:\{f.line}`" }
      sb <+ "|\{f.rule}|\{loc}|\{f.message}|\n"
    }
    sb <+ "\n"
  }
  sb.to_string()
}

///|
fn sev_name_md(s : @engine.Severity) -> String {
  match s {
    Low => "Low"
    Medium => "Medium"
    High => "High"
    Critical => "Critical"
  }
}

///|
/// Markdown 摘要的行数（用于测试与 CI 断言）
pub fn summary_md_lines(r : Report) -> Int32 {
  summary_md(r).split("\n").collect().length()
}
