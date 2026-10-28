///|
/// SARIF 2.1.0 输出：与 GitHub Code Scanning 兼容的静态分析结果格式。
/// 每条 finding 映射为一条 result；规则元数据来自 engine 的规则目录。

///|
/// severity → SARIF level
fn sarif_level(sev : @engine.Severity) -> String {
  match sev {
    Critical => "error"
    High => "error"
    Medium => "warning"
    Low => "note"
  }
}

///|
/// 构造 SARIF results 数组
fn sarif_results(r : Report) -> Array[Json] {
  r.findings.map(f => {
    let loc : Json = if f.file == "" {
      { "message": { "text": "module metadata (\{f.file})" } }
    } else {
      {
        "message": { "text": "\{f.file}:\{f.line}" },
        "physicalLocation": {
          "artifactLocation": { "uri": f.file },
          "region": { "startLine": f.line },
        },
      }
    }
    {
      "ruleId": f.rule,
      "level": sarif_level(f.severity),
      "message": { "text": f.message },
      "locations": [loc],
    }
  })
}

///|
/// 完整 SARIF 文档（run 级元数据 + rules + results）
pub fn to_sarif(r : Report) -> String {
  let rules : Array[Json] = []
  for doc in @engine.rules_catalog() {
    rules.push({
      "id": doc.id,
      "name": doc.id,
      "shortDescription": { "text": doc.title },
      "fullDescription": { "text": doc.triggers },
      "properties": {
        "category": doc.category,
        "default_severity": doc.default_severity,
        "example": doc.example,
        "mitigation": doc.mitigation,
      },
    })
  }
  let doc : Json = {
    "version": "2.1.0",
    "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
    "runs": [
      {
        "tool": {
          "driver": {
            "name": "mooncake-audit",
            "informationUri": "https://mooncakes.io/docs/#/minie135/mooncake-audit",
            "rules": rules,
          },
        },
        "properties": {
          "module": r.module,
          "version": r.version,
          "risk": r.risk,
          "verdict": r.verdict,
        },
        "results": sarif_results(r),
      },
    ],
  }
  doc.stringify(indent=2)
}
