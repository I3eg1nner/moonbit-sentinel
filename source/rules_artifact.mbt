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
/// 对包内非源码文件的 S10 判定：
/// - 平台二进制魔数 → High（dropper 强信号）
/// - 嵌套压缩包 → Medium（运行时解包投递）
/// - 带 shebang 的可执行脚本 → Medium
pub fn s10_artifact(
  relp : String,
  head : Bytes,
  is_archive : Bool,
  is_script : Bool,
) -> Array[@engine.Finding] {
  let fs : Array[@engine.Finding] = []
  if !is_archive && !is_script {
    match detect_binary_magic(head) {
      Some(kind) =>
        fs.push(s10_finding(relp, High, "embedded \{kind.label()} in package"))
      None => ()
    }
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
  if is_script && has_shebang(head) {
    fs.push(s10_finding(relp, Medium, "executable script with shebang"))
  }
  fs
}
