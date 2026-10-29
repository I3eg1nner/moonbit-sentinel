///|
/// S10：落地产物（dropped artifacts）检测。
/// 恶意包常见的投递形态：直接携带预编译二进制（ELF/PE/Mach-O）、
/// 嵌套压缩包（运行时解出载荷）、可执行脚本。合法包通常以源码分发，
/// 携带平台二进制强烈偏离 MoonBit 生态的源码分发预期。

///|
/// 文件头魔数检查所需的读取长度（覆盖最长魔数 + Mach-O fat header）
const MAGIC_PROBE_LEN = 16

///|
/// 二进制类型
pub(all) enum BinaryKind {
  Elf
  MachO64
  MachO32
  MachOFat
  WindowsPE
} derive(Debug, Eq)

///|
fn BinaryKind::label(self : BinaryKind) -> String {
  match self {
    Elf => "ELF executable"
    MachO64 => "Mach-O 64-bit executable"
    MachO32 => "Mach-O 32-bit executable"
    MachOFat => "Mach-O universal binary"
    WindowsPE => "Windows PE executable"
  }
}

///|
/// 从文件头字节识别可执行格式；None 表示非平台二进制
pub fn detect_binary_magic(head : Bytes) -> BinaryKind? {
  let n = head.length()
  // ELF: 7f 45 4c 46
  if n >= 4 &&
    head[0].to_int() == 0x7f &&
    head[1].to_int() == 0x45 &&
    head[2].to_int() == 0x4c &&
    head[3].to_int() == 0x46 {
    return Some(Elf)
  }
  // Mach-O magic（小端与大端两种）：feedface / feedfacf / cefaedfe / ce fa ed fe
  if n >= 4 {
    let b0 = head[0].to_int()
    let b1 = head[1].to_int()
    let b2 = head[2].to_int()
    let b3 = head[3].to_int()
    if b0 == 0xCF && b1 == 0xFA && b2 == 0xED && b3 == 0xFE {
      return Some(MachO64)
    }
    if b0 == 0xCE && b1 == 0xFA && b2 == 0xED && b3 == 0xFE {
      return Some(MachO32)
    }
    // fat binary: ca fe ba be
    if b0 == 0xCA && b1 == 0xFE && b2 == 0xBA && b3 == 0xBE {
      return Some(MachOFat)
    }
    // PE: "MZ"（DOS header，PE 是其扩展）
    if b0 == 0x4d && b1 == 0x5a {
      return Some(WindowsPE)
    }
  }
  None
}

///|
/// 嵌套压缩包扩展名（包内再携带压缩包是典型 dropper 形态）
pub fn is_nested_archive(name : String) -> Bool {
  name.has_suffix(".zip") ||
  name.has_suffix(".tar.gz") ||
  name.has_suffix(".tgz") ||
  name.has_suffix(".tar.bz2") ||
  name.has_suffix(".tbz2") ||
  name.has_suffix(".tar.xz") ||
  name.has_suffix(".7z") ||
  name.has_suffix(".rar")
}

///|
/// 可执行脚本扩展名（配合 shebang 判定，见 scan_script_head）
pub fn is_script_file(name : String) -> Bool {
  name.has_suffix(".sh") ||
  name.has_suffix(".bash") ||
  name.has_suffix(".py") ||
  name.has_suffix(".pl") ||
  name.has_suffix(".exe.sh")
}

///|
/// 脚本是否带 shebang（#!）——带 shebang 的脚本更接近"可直接执行"
pub fn has_shebang(head : Bytes) -> Bool {
  head.length() >= 2 && head[0].to_int() == 0x23 && head[1].to_int() == 0x21
}

///|
/// 构造 S10 finding
fn s10_finding(
  file : String,
  sev : @engine.Severity,
  detail : String,
) -> @engine.Finding {
  let rd : @engine.RuleDef = {
    id: "S10",
    severity: sev,
    category: @engine.Source,
    description: "dropped artifact",
  }
  rd.finding(file~, line=1, snippet="", message=detail)
}

///|
/// 对包内非源码文件的 S10 判定（data 为文件内容，≤2MB）：
/// - 平台二进制魔数 → High（dropper 强信号）
/// - 良性扩展名 + 可执行魔数 → High（伪装可执行文件）
/// - 嵌套压缩包 → Medium（运行时解包投递）
/// - 带 shebang 的可执行脚本 → Medium
/// - 可执行二进制内嵌危险命令字符串 → Critical（内嵌下载器/反弹 shell）
pub fn s10_artifact(
  relp : String,
  data : Bytes,
  is_archive : Bool,
  is_script : Bool,
) -> Array[@engine.Finding] {
  let fs : Array[@engine.Finding] = []
  let is_binary = match detect_binary_magic(data) {
    Some(kind) => {
      fs.push(s10_finding(relp, High, "embedded \{kind.label()} in package"))
      true
    }
    None => false
  }
  // 伪装：良性扩展名下藏着可执行魔数
  if is_binary && !is_archive && !is_script && is_benign_extension(relp) {
    fs.push(
      s10_finding(
        relp,
        High,
        "disguised executable: benign extension with platform binary magic",
      ),
    )
  }
  if is_archive {
    fs.push(
      s10_finding(
        relp,
        Medium,
        "nested archive in package (runtime dropper indicator)",
      ),
    )
  }
  if is_script && has_shebang(data) {
    fs.push(s10_finding(relp, Medium, "executable script with shebang"))
  }
  if is_binary {
    for f in embedded_command_findings(relp, data) {
      fs.push(f)
    }
  }
  fs
}

///|
/// 常见良性扩展名：这些扩展的文件若检出可执行魔数 → 伪装（High）
pub fn is_benign_extension(name : String) -> Bool {
  let exts = [
    ".png", ".jpg", ".jpeg", ".gif", ".bmp", ".svg", ".webp", ".ico", ".pdf", ".txt",
    ".md", ".json", ".csv", ".html", ".htm", ".css", ".js", ".ts", ".wasm", ".toml",
    ".yaml", ".yml", ".xml", ".mbti", ".zip", ".gz", ".tar", ".ttf", ".otf", ".woff",
    ".woff2",
  ]
  exts.iter().any(e => name.has_suffix(e))
}

///|
/// 从二进制提取可打印 ASCII 字符串（≥6 连续），
/// 用于识别内嵌的 URL / shell 入口 / 下载器命令
pub fn extract_ascii_strings(data : Bytes, min_len : Int32) -> Array[String] {
  let out : Array[String] = []
  let n = data.length()
  let mut start = -1
  for i = 0; i < n; i = i + 1 {
    let c = data[i].to_int()
    let printable = c >= 0x20 && c <= 0x7e
    if printable {
      if start < 0 {
        start = i
      }
    } else {
      if start >= 0 && i - start >= min_len {
        out.push(try! @utf8.decode(data[start:i]))
      }
      start = -1
    }
  }
  if start >= 0 && n - start >= min_len {
    out.push(try! @utf8.decode(data[start:]))
  }
  out
}

///|
/// 内嵌字符串中的危险内容标记（与 rules_decode 的 payload 标记同族但独立维护：
/// 二进制里的字符串上下文更弱，要求更完整的命令形态）
let artifact_string_markers : Array[(Bytes, String)] = [
  (b"/bin/sh", "/bin/sh"),
  (b"/bin/bash", "/bin/bash"),
  (b"curl http", "curl downloader"),
  (b"wget http", "wget downloader"),
  (b"sh -c ", "shell -c"),
  (b"/dev/tcp/", "reverse shell"),
  (b"chmod +x", "chmod +x"),
]

///|
/// 二进制内嵌字符串检查：命中危险标记 → Critical
/// （投递的可执行文件里嵌着下载器/反弹 shell 命令是强恶意信号；
/// 直接在原始字节上匹配，避免字符串编码往返）
fn embedded_command_findings(
  relp : String,
  data : Bytes,
) -> Array[@engine.Finding] {
  let fs : Array[@engine.Finding] = []
  for (marker, label) in artifact_string_markers {
    match bytes_find(data, marker, false) {
      Some(_) =>
        fs.push(
          s10_finding(
            relp,
            Critical,
            "embedded \{label} string in binary artifact",
          ),
        )
      None => ()
    }
  }
  fs
}
