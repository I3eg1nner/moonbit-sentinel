///|
/// 研判提示词：证据预算化——只喂确定性结论、findings 摘要与命中规则的
/// 目录条目，不喂包全文。要求模型只输出 JSON。

///|
fn system_prompt() -> String {
  "You are a supply-chain security analyst adjudicating static-analysis findings for a MoonBit package. You will see the deterministic engine verdict, risk score, findings, and the rule catalog entries for the rules that fired. Respond ONLY with a single JSON object, no markdown fence, in the shape {\"verdict\": \"malicious|suspicious|clean\", \"confidence\": <0.0-1.0>, \"rationale\": \"<= 2 sentences\"}. Judge behavioral intent: legitimate tools (CI runners, proxies, sandbox demos, agent frameworks) legitimately spawn processes, read credentials and open network connections; flag only combinations that look like abuse (exfiltration to hardcoded endpoints, dropped binaries, decode-to-download payloads, persistence writes without user-facing commands). If evidence is ambiguous, prefer suspicious over malicious."
}

///|
fn sev_label(s : @engine.Severity) -> String {
  match s {
    Low => "Low"
    Medium => "Medium"
    High => "High"
    Critical => "Critical"
  }
}

///|
fn findings_block(r : @report.Report) -> String {
  let sb = StringBuilder()
  for f in r.findings {
    sb <+
      "- \{f.rule} \{sev_label(f.severity)} \{f.file}:\{f.line} — \{f.message}\n"
  }
  sb.to_string()
}

///|
fn catalog_block(r : @report.Report) -> String {
  let sb = StringBuilder()
  let seen : Array[String] = []
  for f in r.findings {
    if seen.iter().any(x => x == f.rule) {
      continue
    }
    seen.push(f.rule)
    match @engine.rule_by_id(f.rule) {
      Some(doc) => sb <+ "[\{doc.id}] \{doc.title}: triggers \{doc.triggers}\n"
      None => ()
    }
  }
  sb.to_string()
}

///|
/// 用户消息：确定性结论 + findings + 命中规则条目
pub fn user_prompt(r : @report.Report) -> String {
  let sb = StringBuilder()
  sb <+ "module: \{r.module}@\{r.version}\n"
  sb <+
    "engine verdict: \{r.verdict} (risk \{r.risk}/100, \{r.findings.length()} findings)\n\n"
  sb <+ "findings:\n\{findings_block(r)}\n"
  sb <+ "rule catalog entries for the rules above:\n\{catalog_block(r)}\n"
  sb <+ "Adjudicate now. JSON only."
  sb.to_string()
}

///|
pub fn messages(r : @report.Report) -> Array[Json] {
  [
    { "role": "system", "content": system_prompt() },
    { "role": "user", "content": user_prompt(r) },
  ]
}
