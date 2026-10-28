///|
/// 研判主流程：单次调用；JSON 解析失败时带纠正提示重试一次

///|
pub(all) struct AssessOutcome {
  assessment : Assessment
  attempts : Int // 1=首次成功，2=重试后成功
} derive(Debug)

///|
/// 极简智能体：system+user 单轮；失败重试一次（附"上次输出不是合法 JSON"提示）
pub async fn assess_with(
  r : @report.Report,
  client : OpenAiClient,
) -> AssessOutcome? {
  let model = client.model_name()
  let msgs = messages(r)
  match parse_assessment(client.complete(msgs), model) {
    Some(a) => return Some({ assessment: a, attempts: 1, })
    None => ()
  }
  let retry_msgs : Array[Json] = [
    {
      "role": "system",
      "content": "Your previous reply was not valid JSON in the required shape. Output ONLY the JSON object.",
    },
    ..msgs,
  ]
  match parse_assessment(client.complete(retry_msgs), model) {
    Some(a) => Some({ assessment: a, attempts: 2, })
    None => None
  }
}
