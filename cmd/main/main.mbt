///|
pub(all) enum Cmd {
  Scan(
    dir~ : String,
    module~ : String,
    version~ : String,
    json~ : Bool,
    min_sev~ : Int,
    format~ : String,
    explain~ : Bool,
    fail_on~ : String,
    llm~ : Bool
  )
  Rules
  Version
  Help
} derive(Debug)

///|
/// 输出格式：human（默认）/ json / sarif
fn parse_format(v : String) -> String {
  if v is ("json" | "sarif" | "human" | "md") {
    v
  } else {
    "human"
  }
}

///|
pub fn parse_args(args : Array[String]) -> Cmd {
  if args.length() == 0 {
    return Help
  }
  if args[0] is ("rules" | "--rules") {
    return Rules
  }
  if args[0] is ("--version" | "-V") {
    return Version
  }
  if args[0] != "scan" {
    return Help
  }
  let mut dir = ""
  let mut module = ""
  let mut version = ""
  let mut json = false
  let mut min_sev = 0
  let mut format = "human"
  let mut explain = false
  let mut fail_on = ""
  let mut llm = false
  let n = args.length()
  let mut i = 1
  while i < n {
    let a = args[i]
    if a == "--json" {
      json = true
      format = "json"
    } else if a == "--explain" {
      explain = true
    } else if a == "--llm" {
      llm = true
    } else if a == "--fail-on" {
      if i + 1 < n && args[i + 1] is ("suspicious" | "malicious") {
        i += 1
        fail_on = args[i]
      }
    } else if a is ("--module" | "--version" | "--min-severity" | "--format") {
      if i + 1 < n {
        i += 1
        match a {
          "--module" => module = args[i]
          "--version" => version = args[i]
          "--format" => format = parse_format(args[i])
          _ =>
            min_sev = match @engine.parse_severity(args[i]) {
              Some(s) => s.rank()
              None => 0
            }
        }
      }
      // flag missing its value at the end: ignore the flag
    } else if a.has_prefix("--") {
      () // unknown flag: ignore
    } else if dir is "" {
      dir = a
    }
    i += 1
  }
  Scan(
    dir~,
    module~,
    version~,
    json~,
    min_sev~,
    format~,
    explain~,
    fail_on~,
    llm~,
  )
}

///|
pub fn filter_min(r : @report.Report, min_rank : Int) -> @report.Report {
  if min_rank <= 0 {
    return r
  }
  let kept = r.findings.filter(f => f.severity.rank() >= min_rank)
  let risk = @score.risk_of(kept)
  { ..r, findings: kept, risk, verdict: @score.verdict_of(risk).to_string(), }
}

///|
fn usage() -> String {
  "mooncake-audit — static supply-chain detector for mooncakes.io packages\n\n" +
  "usage:\n" +
  "  mooncake-audit scan <dir> [options]   scan an extracted package directory\n" +
  "  mooncake-audit rules                  print the rule catalog\n" +
  "\n" +
  "options:\n" +
  "  --module m            module name recorded in the report\n" +
  "  --version v           package version for the report\n" +
  "  --min-severity s      low|medium|high|critical filter\n" +
  "  --format s            human|json|sarif|md (default human)\n" +
  "  --explain             print the score breakdown (implies human format)\n" +
  "  --fail-on s           exit non-zero when verdict is malicious|suspicious (CI)\n" +
  "  --llm                 adjudicate the verdict with an LLM (env-configured, advisory)\n"
}

///|
async fn main {
  let args = @env.args()
  let user_args : Array[String] = if args.length() > 1 {
    args[1:].to_owned()
  } else {
    []
  }
  match parse_args(user_args) {
    Help => println(usage())
    Rules => println(@engine.catalog_text())
    Version => println("mooncake-audit 0.4.1")
    Scan(..) as c => {
      let r = try {
        let opts : @scan.ScanOptions = { authoritative_name: c.module, }
        @scan.run_scan(c.dir, opts)
      } catch {
        e => {
          let err : Json = { "module": c.dir, "error": "\{e}" }
          println(err.stringify())
          return
        }
      }
      let r = if !(c.module is "") { { ..r, module: c.module, } } else { r }
      let r = if !(c.version is "") { { ..r, version: c.version, } } else { r }
      let r = filter_min(r, c.min_sev)
      // LLM 研判（advisory）：env 缺失时提示并跳过
      let mut assessment : @assess.Assessment? = None
      if c.llm {
        match @assess.client_from_env(k => @env.get_env_var(k)) {
          Some(client) =>
            match @assess.assess_with(r, client) {
              Some(outcome) => {
                assessment = Some(outcome.assessment)
                let a = outcome.assessment
                println(
                  "llm adjudication (\{a.model}, attempts \{outcome.attempts}): \{a.verdict} confidence=\{a.confidence}\n  \{a.rationale}",
                )
              }
              None =>
                println("llm adjudication: model output unparsable after retry")
            }
          None =>
            println(
              "llm adjudication skipped: set MOONCAKE_LLM_KEY (or API_KEY)",
            )
        }
      }
      if c.explain {
        println(@score.explain_text(r))
        return
      }
      if c.format is "sarif" {
        println(@report.to_sarif(r))
      } else if c.format is "md" {
        println(@report.summary_md(r))
      } else if c.format is "json" {
        match assessment {
          Some(a) => {
            // Json Object 只读：借 Json::object 重建带 assessment 的对象
            let merged : Map[String, Json] = {}
            match r.to_json() {
              Object(m) =>
                for k, v in m {
                  merged[k] = v
                }
              _ => ()
            }
            merged["assessment"] = a.to_json()
            println(Json::object(merged).stringify())
          }
          None => println(r.to_json_string())
        }
      } else {
        println(@report.human_summary(r))
      }
      // CI 退出码：verdict 达到 --fail-on 阈值时非零退出
      if !(c.fail_on is "") {
        let breach = if c.fail_on is "malicious" {
          r.verdict is "Malicious"
        } else if c.fail_on is "suspicious" {
          r.verdict is ("Malicious" | "Suspicious")
        } else {
          false
        }
        if breach {
          fail(
            "mooncake-audit: verdict \{r.verdict} meets --fail-on \{c.fail_on}",
          )
        }
      }
    }
  }
}
