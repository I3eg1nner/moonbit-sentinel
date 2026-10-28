///|
/// S04 升级：对长 base64 载荷做真实解码检查。
/// 静态混淆只有解码后才暴露意图：解码后的字节若含 URL、shell 入口、
/// 下载器或 shebang，则从 High 升级为 Critical（"decoded payload"）。
/// 解码结果本身仍是 base64 主导 → 标记 multi-stage（多级解壳）。

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
/// 字节串包含 ASCII 模式（朴素匹配）
fn bytes_contains(hay : Bytes, needle : Bytes) -> Bool {
  let n = hay.length()
  let m = needle.length()
  if m == 0 || n < m {
    return false
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
      return true
    }
  }
  false
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
  for (start, len) in extract_runs(ctx.content, @matchers.is_b64, 48) {
    guard len <= 4096 else { continue } // 超长 blob 解码成本高，交给原 S04 长度规则
    let candidate = ctx.content[start:start + len].to_owned()
    match try_decode_b64(candidate) {
      Some(bytes) => {
        let mut danger = ""
        for i, marker in payload_markers {
          if bytes_contains(bytes, marker) {
            danger = payload_marker_names[i]
            break
          }
        }
        // 无标记但解码结果仍主要是 base64 → 多级解壳
        // 0.97：普通英文文本约 90% 落在 base64 字母表，必须高于此；真正的内层 base64 接近 1.0
        if danger == "" && b64_ratio(bytes) > 0.97 && bytes.length() > 48 {
          danger = "multi-stage base64"
        }
        if danger != "" {
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
