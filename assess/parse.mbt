///|
/// 响应解析与研判主流程

///|
/// 从模型输出中提取 JSON 子串（容忍 ```json 围栏与前后噪声）
fn extract_json_object(text : String) -> String? {
  let start = match text.find("{") {
    Some(i) => i
    None => return None
  }
  // 反向扫描找最后一个 '}'
  let bytes = text
  let mut end = -1
  let n = bytes.length()
  for i = n - 1; i >= 0; i = i - 1 {
    if bytes[i] == 125 {
      end = i
      break
    }
  }
  if end <= start {
    return None
  }
  Some(text[start:end + 1].to_owned())
}

///|
/// 解析 Assessment；字段缺失/verdict 非法/confidence 越界 → None
pub fn parse_assessment(text : String, model : String) -> Assessment? {
  let raw = match extract_json_object(text) {
    Some(t) => t
    None => return None
  }
  let j = @json.parse(raw) catch { _ => return None }
  let verdict = match j {
    Object(m) =>
      match m.get("verdict") {
        Some(String(v)) => v.to_lower()
        _ => return None
      }
    _ => return None
  }
  if !valid_verdicts().iter().any(v => v == verdict) {
    return None
  }
  let confidence = match j {
    Object(m) =>
      match m.get("confidence") {
        Some(Number(c)) => if c >= 0.0 && c <= 1.0 { c } else { return None }
        _ => 0.5
      }
    _ => 0.5
  }
  let rationale = match j {
    Object(m) =>
      match m.get("rationale") {
        Some(String(s)) => s
        _ => ""
      }
    _ => ""
  }
  Some({ verdict, confidence, rationale, model, })
}
