///|
/// 评分解释：把 risk 总分分解为逐 finding 的权重表，
/// 支撑 `--explain` 输出（可审计的判定依据）。

///|
pub(all) struct ScoreLine {
  rule : String
  severity : @engine.Severity
  weight : Int
  file : String
  note : String
} derive(Debug)

///|
/// 逐 finding 的分解行（与 risk_of 的求和口径一致）
pub fn explain_lines(fs : Array[@engine.Finding]) -> Array[ScoreLine] {
  fs.map(f => {
    let note = match @engine.rule_by_id(f.rule) {
      Some(doc) => doc.title
      None => ""
    }
    {
      rule: f.rule,
      severity: f.severity,
      weight: f.severity.weight(),
      file: f.file,
      note,
    }
  })
}

///|
/// 人类可读的分解表：权重求和 → risk → verdict
pub fn explain_text(r : @report.Report) -> String {
  let sb = StringBuilder()
  sb <+ "score breakdown for \{r.module}@\{r.version}\n"
  sb <+ "-----------------------------------------\n"
  let mut total = 0
  for line in explain_lines(r.findings) {
    total = total + line.weight
    sb <+
      "\{line.rule}  \{sev_name(line.severity)}  +\{line.weight}  \{line.file}\n"
    if line.note != "" {
      sb <+ "         \{line.note}\n"
    }
  }
  sb <+ "-----------------------------------------\n"
  sb <+ "risk \{total} -> verdict \{r.verdict}\n"
  sb.to_string()
}

///|
fn sev_name(s : @engine.Severity) -> String {
  match s {
    Low => "Low"
    Medium => "Medium"
    High => "High"
    Critical => "Critical"
  }
}
