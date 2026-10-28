///|
/// End-to-end canary fixtures (see canaries/README.md): each fixture pins a
/// slice of the scoring model through the full run_scan pipeline.

///|
fn canary(name : String) -> String {
  "canaries/" + name
}

///|
async test "canary behavior_exfil is malicious" {
  let r = @scan.run_scan(canary("behavior_exfil"), { authoritative_name: "", })
  // S01(10)+S02(10)+S99(25)+S04 decoded payload(25) = 70
  inspect(r.risk >= 50, content="true")
  inspect(r.verdict, content="Malicious")
}

///|
async test "canary prebuild_dropper is malicious" {
  let r = @scan.run_scan(canary("prebuild_dropper"), { authoritative_name: "", })
  // S06(25)+S03(25)+S01(10)+M03(5)+M04(1) = 66
  inspect(r.risk >= 50, content="true")
  inspect(r.verdict, content="Malicious")
}

///|
async test "canary obfuscated_exfil is suspicious" {
  let r = @scan.run_scan(canary("obfuscated_exfil"), { authoritative_name: "", })
  // S04 decoded payload Critical(25) = 25
  inspect(r.risk >= 15, content="true")
  inspect(r.verdict, content="Suspicious")
}

///|
async test "canary benign_http is clean" {
  let r = @scan.run_scan(canary("benign_http"), { authoritative_name: "", })
  inspect(r.risk, content="0")
  inspect(r.verdict, content="Clean")
}

///|
async test "canary dropped_binary is flagged for disguised artifacts" {
  let r = @scan.run_scan(canary("dropped_binary"), { authoritative_name: "", })
  // 魔数 ELF(High) + 伪装(High) + 内嵌 curl 下载器(Critical)；按规则收敛后 S10=Critical(25)
  let s10 = r.findings.iter().filter(f => f.rule == "S10").collect()
  inspect(s10.length(), content="3")
  inspect(s10.iter().any(f => f.message.contains("disguised")), content="true")
  inspect(
    s10
    .iter()
    .any(f => f.severity == Critical && f.message.contains("downloader")),
    content="true",
  )
  inspect(r.risk >= 25, content="true")
  inspect(r.verdict, content="Suspicious")
}
