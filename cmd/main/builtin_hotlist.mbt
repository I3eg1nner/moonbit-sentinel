///|
/// 内置热门模块清单（mooncakes.io 下载量 Top-100，2026-10 快照）。
/// 未提供 --hotlist 文件时使用，保证 typo-squatting 检测开箱即用；
/// 数据来源为公开注册表统计，可随时用 --hotlist 覆盖。
let builtin_hotlist : Array[String] = [
  "001-Elsa/gerberguard", "001-Elsa/medseal", "001-Elsa/mooncron", "001-Elsa/moonjmap",
  "001-Elsa/moonpack", "001-Elsa/ptp-audit", "0717lee/moonav1", "0717lee/moonhostabi",
  "0717lee/pixelforge", "0Ayachi0/elk", "0Ayachi0/GB18030", "0Ayachi0/math", "0Ayachi0/SwissTable",
  "0xA672/moonbit_version_cli", "0xA672/moonver", "0xA672/moonwasm_probe", "0xA672/mwp",
  "0xA672/strip", "100kkk/moon-schedule", "1123Javayanglei/moonbit_claude_proxy",
  "123123213weqw/moonbit_jwt", "123123213weqw/moonbit_mcp", "123123213weqw/moon_configweave",
  "123123213weqw/moon_historycheck", "123123213weqw/moon_policyforge", "123123213weqw/moon_proto",
  "123123213weqw/moon_pyversion", "123123213weqw/moon_scrub", "123123213weqw/moon_taskforge",
  "13131116363/routeable", "15614376790/moon-weblink", "1726914517-spec/moon_otp",
  "1726914517-spec/moonproxy", "17731189258/sbs", "202306123/lib_mbt", "2111950632/robots-gate",
  "2111950632/szs", "2200732518gjy/moonfountain", "2200732518gjy/moonstix", "2200732518gjy/moonwell",
  "2227057182/moonshim", "2459822546/fwshz", "2515050242/agentcheck", "2515050242/cbor",
  "2515050242/fiducial_marker", "2515050242/moonagentcheck", "2515050243qyf/moon_bencode",
  "2515050243qyf/moonbit-geofield", "2973181701/moongpx", "2d5rrr333/moonbridge",
  "2d5rrr333/moonform", "2d5rrr333/moonwebtest", "2d5rrr333/mtab", "2d5rrr333/toolsfx-moonbit",
  "3smallpig/mooncutstock", "404-32/moon-codeowners", "404-32/moon-pe-inspect", "668xin/modbus_lint",
  "668xin/moonbit-chart", "668xin/moonbit-observe", "668xin/moon_epub", "6P66006/moon-problem-details",
  "6P66006/moon-sfv", "918154429/moonguard", "A-23187/encoding", "Across2005/harness-self-evolution",
  "Across2005/MoonBit-memory", "Across2005/yimai_prophecy_moonbit", "AdUhTkJm/assembler",
  "AdUhTkJm/bitviewer", "AdUhTkJm/moonc", "AdUhTkJm/nummoon", "AdUhTkJm/sat-solver",
  "AdUhTkJm/u8str", "AdUhTkJm/wasmtools", "aerbsi832/safetensors-toolkit", "Ag108/MoonCache",
  "Ag108/MoonReduce", "Ag108/MoonSRC", "Ag108/moon-wasi", "agentdebug799/moonbit-triage",
  "AlexenderSokolov/moonflowgraph", "AlexenderSokolov/moonmetamath", "AlexenderSokolov/moonportcheck",
  "AlexenderSokolov/moonsplit", "AlexenderSokolov/moontrack", "alicedhaha/minivcd_mbt",
  "alicedhaha/moonrcinspect", "allain/mongodb", "allenli178/moon-qrcode", "Allianaab2m/aya",
  "allwefantasy/readline.mbt", "aloyscc/moon_cel", "amistozy/prolog", "amor2025/biginteger",
  "amor2025/convert", "amor2025/fraction", "amor2025/moonNum", "amor2025/pad", "anccnuer/onho",
]

///|
/// 热门清单：优先用户提供的文件，否则回退内置清单
pub fn effective_hotlist(user : Array[String]) -> Array[String] {
  if user.length() > 0 {
    return user
  }
  builtin_hotlist
}
