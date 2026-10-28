///|
fn demo_report() -> @report.Report {
  let rd : @engine.RuleDef = {
    id: "S01",
    severity: @engine.High,
    category: @engine.Source,
    description: "network exfiltration surface",
  }
  {
    module: "evil/demo",
    version: "0.1.0",
    risk: 45,
    verdict: "Suspicious",
    findings: [
      rd.finding(
        file="src/a.mbt",
        line=3,
        snippet="http://13.37.13.37/u",
        message="raw ip url",
      ),
    ],
    errors: [],
  }
}

///|
test "user_prompt carries module, verdict and findings" {
  let p = @assess.user_prompt(demo_report())
  inspect(p.contains("evil/demo@0.1.0"), content="true")
  inspect(p.contains("engine verdict: Suspicious (risk 45/100"), content="true")
  inspect(p.contains("S01 High src/a.mbt:3"), content="true")
  inspect(p.contains("raw ip url"), content="true")
}

///|
test "parse_assessment accepts clean json and fenced json" {
  let direct = @assess.parse_assessment(
    "{\"verdict\":\"malicious\",\"confidence\":0.9,\"rationale\":\"decoded downloader payload\"}",
    "m",
  )
  inspect(direct is Some(_), content="true")
  inspect(
    match direct {
      Some(a) => a.verdict == "malicious" && a.confidence == 0.9
      None => false
    },
    content="true",
  )
  let fenced = @assess.parse_assessment(
    "```json\n{\"verdict\":\"clean\",\"confidence\":0.4,\"rationale\":\"ordinary http client\"}\n```",
    "m",
  )
  inspect(
    match fenced {
      Some(a) => a.verdict == "clean"
      None => false
    },
    content="true",
  )
}

///|
test "parse_assessment rejects garbage and invalid fields" {
  inspect(@assess.parse_assessment("no json here", "m") is None, content="true")
  inspect(
    @assess.parse_assessment("{\"verdict\":\"benign\",\"confidence\":0.9}", "m")
    is None,
    content="true",
  )
  inspect(
    @assess.parse_assessment("{\"verdict\":\"clean\",\"confidence\":1.7}", "m")
    is None,
    content="true",
  )
  // confidence 缺失时默认 0.5，verdict 仍可用
  inspect(
    @assess.parse_assessment("{\"verdict\":\"suspicious\"}", "m")
    is Some({ confidence: 0.5, .. }),
    content="true",
  )
}

///|
test "client_from_env resolves explicit and fallback vars" {
  let mk = (m : Map[String, String]) => @assess.client_from_env(k => m.get(k))
  inspect(
    mk({
      "MOONCAKE_LLM_KEY": "sk-x",
      "MOONCAKE_LLM_BASE_URL": "https://llm.example.com/v1",
      "MOONCAKE_LLM_MODEL": "glm",
    })
    is Some({ base_url: "https://llm.example.com/v1", model: "glm", .. }),
    content="true",
  )
  // 兼容通用 API_KEY/Base_URL/Model
  inspect(
    mk({ "API_KEY": "k", "Base_URL": "https://p/v1", "Model": "M" })
    is Some({ api_key: "k", .. }),
    content="true",
  )
  // 无任何 key → None
  inspect(mk({}) is None, content="true")
}
