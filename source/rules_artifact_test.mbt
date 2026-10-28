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
