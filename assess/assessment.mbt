///|
/// LLM 研判结论：advisory，不覆盖确定性 verdict
pub(all) struct Assessment {
  verdict : String // "malicious" | "suspicious" | "clean"
  confidence : Double
  rationale : String
  model : String
} derive(Debug)

///|
pub impl ToJson for Assessment with fn to_json(self) -> Json {
  {
    "verdict": self.verdict,
    "confidence": self.confidence,
    "rationale": self.rationale,
    "model": self.model,
  }
}

///|
/// 合法 verdict 值
pub fn valid_verdicts() -> Array[String] {
  ["malicious", "suspicious", "clean"]
}
