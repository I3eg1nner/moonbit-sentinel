///|
test "parse_args scan with json flags" {
  match parse_args(["scan", "/tmp/x", "--json", "--format", "sarif"]) {
    Scan(dir~, module~, version~, json~, min_sev~, ..) => {
      inspect(dir, content="/tmp/x")
      inspect(module, content="")
      inspect(version, content="")
      inspect(json, content="true")
      inspect(json, content="true")
      inspect(min_sev, content="0")
    }
    _ => fail("expected Scan")
  }
}

///|
test "parse_args help without scan subcommand" {
  match parse_args([]) {
    Help => ()
    _ => fail("expected Help")
  }
  match parse_args(["report", "/tmp/x"]) {
    Help => ()
    _ => fail("expected Help")
  }
}

///|
test "parse_args flags in any order with value overrides" {
  match
    parse_args([
      "scan", "--min-severity", "high", "--json", "--module", "evil/x", "--version",
      "9.9.9", "/d",
    ]) {
    Scan(dir~, module~, version~, json~, min_sev~, ..) => {
      inspect(dir, content="/d")
      inspect(module, content="evil/x")
      inspect(version, content="9.9.9")
      inspect(json, content="true")
      inspect(min_sev, content="2")
    }
    _ => fail("expected Scan")
  }
}

///|
test "parse_args first positional wins and dangling flag value ignored" {
  match parse_args(["scan", "/first", "/second", "--format"]) {
    Scan(dir~, ..) => inspect(dir, content="/first")
    _ => fail("expected Scan")
  }
}

///|
test "parse_args invalid min-severity falls back to no filter" {
  match parse_args(["scan", "/d", "--min-severity", "bogus"]) {
    Scan(min_sev~, ..) => inspect(min_sev, content="0")
    _ => fail("expected Scan")
  }
}

///|
fn cli_finding(rule : String, sev : @engine.Severity) -> @engine.Finding {
  {
    rule,
    severity: sev,
    category: @engine.Source,
    file: "a.mbt",
    line: 1,
    snippet: "",
    message: "m",
  }
}

///|
test "filter_min keeps rank-qualified findings and re-scores" {
  let r : @report.Report = {
    module: "evil/x",
    version: "0.1.0",
    risk: 16,
    verdict: "Suspicious",
    findings: [
      cli_finding("S01", @engine.High),
      cli_finding("S04", @engine.Medium),
      cli_finding("M02", @engine.Low),
    ],
    errors: [],
  }
  let filtered = filter_min(r, 2)
  inspect(filtered.findings.length(), content="1")
  inspect(filtered.risk, content="10")
  inspect(filtered.verdict, content="Clean")
  let unchanged = filter_min(r, 0)
  inspect(unchanged.risk, content="16")
  inspect(unchanged.findings.length(), content="3")
}
