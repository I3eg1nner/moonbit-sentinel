///|
/// S04 升级：对长 base64 载荷做真实解码检查。
/// 静态混淆只有解码后才暴露意图：解码后的字节若含 URL、shell 入口、
/// 下载器或 shebang，则从 High 升级为 Critical（"decoded payload"）。
/// 解码结果本身仍是 base64 主导 → 标记 multi-stage（多级解壳）。

///|
/// 数据表防护（如 tokenizer 词表）：单文件载荷告警至多 3 条
const MAX_PAYLOAD_FINDINGS = 3

///|
/// payload 危险标记（ASCII 字节串）
let payload_markers : Array[Bytes] = [
  b"http://", b"https://", b"/bin/sh", b"/bin/bash", b"sh -c", b"#!/", b"curl ",
  b"wget ", b"eval(",
]

///|
/// 标记的人类可读名（与 payload_markers 同序）
let payload_marker_names : Array[String] = [
  "http url", "https url", "/bin/sh", "/bin/bash", "sh -c", "shebang", "downloader (curl)",
  "downloader (wget)", "eval",
]

///|
/// 提取满足 pred 的连续游程 ≥ min_len 的 (start, len) 列表
fn extract_runs(
  s : String,
  pred : (UInt16) -> Bool,
  min_len : Int,
) -> Array[(Int, Int)] {
  let out : Array[(Int, Int)] = []
  let n = s.length()
  let mut start = -1
  for i = 0; i < n; i = i + 1 {
    if pred(s[i]) {
      if start < 0 {
        start = i
      }
    } else {
      if start >= 0 && i - start >= min_len {
        out.push((start, i - start))
      }
      start = -1
    }
  }
  if start >= 0 && n - start >= min_len {
    out.push((start, n - start))
  }
  out
}

///|
/// URL 标记后是否跟随主机名形态（≥4 个字母数字后接 . 或数字点）：
/// 词表 token（如单独的 "http://"）不含主机，不应告警
fn url_has_host(hay : Bytes, at : Int) -> Bool {
  let n = hay.length()
  let mut i = at
  let mut run = 0
  while i < n {
    let c = hay[i].to_int()
    if (c >= 97 && c <= 122) || (c >= 65 && c <= 90) || (c >= 48 && c <= 57) {
      run = run + 1
      i = i + 1
    } else {
      break
    }
  }
  // IP 形态：数字.数字（至少一段点分）
  if run >= 1 && i < n && hay[i].to_int() == 46 {
    let mut j = i + 1
    let mut digits = 0
    while j < n {
      let c = hay[j].to_int()
      if c >= 48 && c <= 57 {
        digits = digits + 1
        j = j + 1
      } else {
        break
      }
    }
    if digits >= 1 {
      return true
    }
  }
  if run < 4 {
    return false
  }
  // 主机后需接 '.'（域名）或 ':'（端口）
  i < n && (hay[i].to_int() == 46 || hay[i].to_int() == 58)
}

///|
/// 返回模式首次出现位置；URL 类模式（http://、https://）要求后随主机名
fn bytes_find(hay : Bytes, needle : Bytes, is_url : Bool) -> Int? {
  let n = hay.length()
  let m = needle.length()
  if m == 0 || n < m {
    return None
  }
  for i = 0; i <= n - m; i = i + 1 {
    let mut hit = true
    for j = 0; j < m; j = j + 1 {
      if hay[i + j] != needle[j] {
        hit = false
        break
      }
    }
    if hit {
      if is_url && !url_has_host(hay, i + m) {
        continue
      }
      return Some(i)
    }
  }
  None
}

///|
/// 字节串中 base64 字母表字符占比（识别多级解壳）
fn b64_ratio(hay : Bytes) -> Double {
  if hay.length() == 0 {
    return 0.0
  }
  let mut ok = 0
  for i = 0; i < hay.length(); i = i + 1 {
    let c = hay[i].to_int()
    if (c >= 65 && c <= 90) ||
      (c >= 97 && c <= 122) ||
      (c >= 48 && c <= 57) ||
      c == 43 ||
      c == 47 ||
      c == 61 {
      ok = ok + 1
    }
  }
  ok.to_double() / hay.length().to_double()
}

///|
/// 尝试解码 base64 候选（自动补 padding，忽略内嵌空白）；失败返回 None
fn try_decode_b64(candidate : String) -> Bytes? {
  let padded = candidate + "=".repeat((4 - candidate.length() % 4) % 4)
  Some(@base64.decode(padded, ignore_whitespace=true)) catch {
    _ => None
  }
}

///|
/// 对 ctx 中长 base64 游程解码检查；返回要追加的 Critical findings。
/// 仅生产文件调用（测试夹具常有编码样本，属正常用途）。
pub fn s04_payload(ctx : SourceCtx) -> Array[@engine.Finding] {
  let rd : @engine.RuleDef = {
    id: "S04",
    severity: @engine.Critical,
    category: @engine.Source,
    description: "decoded payload",
  }
  let fs : Array[@engine.Finding] = []
  let seen_lines : Array[Int] = []
  let runs = extract_runs(ctx.content, @matchers.is_b64, 48)
  // 数据表识别（tokenizer 词表/模型清单）：海量短编码行（>20 个游程）不是攻击载荷
  if runs.length() > 20 {
    return fs
  }
  for (start, len) in runs {
    guard len <= 4096 else { continue } // 超长 blob 解码成本高，交给原 S04 长度规则
    let candidate = ctx.content[start:start + len].to_owned()
    match try_decode_b64(candidate) {
      Some(bytes) => {
        let mut danger = ""
        for i, marker in payload_markers {
          let is_url = payload_marker_names[i].contains("url")
          match bytes_find(bytes, marker, is_url) {
            Some(_) => {
              danger = payload_marker_names[i]
              break
            }
            None => ()
          }
        }
        // 无标记但解码结果仍主要是 base64 → 多级解壳
        // 0.97：普通英文文本约 90% 落在 base64 字母表，必须高于此；真正的内层 base64 接近 1.0
        if danger == "" && b64_ratio(bytes) > 0.97 && bytes.length() > 48 {
          danger = "multi-stage base64"
        }
        if danger != "" {
          if fs.length() >= MAX_PAYLOAD_FINDINGS {
            break
          }
          let line = ctx.lines.line_of(start)
          if seen_lines.iter().any(l => l == line) {
            continue
          }
          seen_lines.push(line)
          fs.push(
            rd.finding(
              file=ctx.file,
              line~,
              snippet=ctx.lines.snippet(ctx.content, line),
              message="decoded payload contains \{danger}",
            ),
          )
        }
      }
      None => ()
    }
  }
  fs
}
