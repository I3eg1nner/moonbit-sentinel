///|
/// S06 命令链危险分级：对 pre-build 命令做模式分析而非关键词并集。
/// 三级：
/// - Critical：pipe-to-shell（`| sh`/`| bash`/`| python`）、命令替换 `$(`/反引号、
///   base64 解码执行（`base64 -d`/`--decode`）、反弹 shell（`/dev/tcp/`、`nohup`）、
///   下载后执行（curl/wget 与 shell/sh/chmod +x 组合出现）
/// - High：含下载器（curl/wget/http）或解释器（python/node）但无上述组合
/// - High（基线）：pre-build 钩子本身存在（构建期任意命令执行面）

///|
/// pipe 直通解释器：`| sh`、`| bash`、`| zsh`、`| python` 等（容忍空格变体）
fn pipe_to_shell(cmd : String) -> String? {
  let shells = ["sh", "bash", "zsh", "dash", "python", "python3", "node"]
  for sh in shells {
    for sep in ["| ", "|", "|  "] {
      let pat = sep + sh + " "
      if cmd.contains(pat) || cmd.has_suffix(sep + sh) {
        return Some("pipe to \{sh}")
      }
    }
  }
  None
}

///|
/// 命令链危险分类；返回 (严重度, 命中说明)。无命中说明时为基线 High。
pub fn classify_prebuild(cmd : String) -> (@engine.Severity, String) {
  match pipe_to_shell(cmd) {
    Some(reason) => return (Critical, reason)
    None => ()
  }
  // 命令替换
  if cmd.contains("$(") || cmd.contains("`") {
    return (Critical, "command substitution")
  }
  // base64 解码执行链
  if cmd.contains("base64 -d") || cmd.contains("base64 --decode") {
    return (Critical, "base64 decode in command")
  }
  // 反弹 shell / 后台驻留
  if cmd.contains("/dev/tcp/") || cmd.contains("nohup ") {
    return (Critical, "reverse shell indicator")
  }
  // 下载 + 执行组合（同一命令里同时出现下载器与执行入口）
  let has_dl = cmd.contains("curl") ||
    cmd.contains("wget") ||
    cmd.contains("http")
  let has_exec = cmd.contains("sh ") ||
    cmd.contains("bash") ||
    cmd.contains("chmod +x") ||
    cmd.contains("source ")
  if has_dl && has_exec {
    return (Critical, "download then execute")
  }
  if has_dl {
    return (High, "downloader present")
  }
  if cmd.contains("python") || cmd.contains("node ") {
    return (High, "interpreter present")
  }
  if cmd.contains("rm -rf") {
    return (High, "destructive delete")
  }
  (High, "pre-build hook")
}

///|
/// S06：pre-build 钩子存在 → High（基线）；命令链含上述模式 → 升级 Critical
pub fn s06(pkg : PkgInfo, pkgfile : String) -> Array[@engine.Finding] {
  let fs : Array[@engine.Finding] = []
  for cmd in pkg.pre_build {
    let (sev, reason) = classify_prebuild(cmd)
    let rd : @engine.RuleDef = {
      id: "S06",
      severity: sev,
      category: @engine.Source,
      description: "pre-build hook",
    }
    fs.push(
      rd.finding(
        file=pkgfile,
        line=1,
        snippet=cmd,
        message="pre-build command: \{reason}",
      ),
    )
  }
  fs
}
