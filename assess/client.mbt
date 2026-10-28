///|
/// LLM client：注入式接口（离线可测）+ OpenAI 兼容实现

///|
/// OpenAI 兼容端点实现（/chat/completions）
pub(all) struct OpenAiClient {
  base_url : String // 形如 https://host/v1
  api_key : String
  model : String
} derive(Debug)

///|
fn content_of(j : Json) -> String raise {
  match j {
    Object(m) =>
      match m.get("choices") {
        Some(Array([first, ..])) =>
          match first {
            Object(choice) =>
              match choice.get("message") {
                Some(Object(message)) =>
                  match message.get("content") {
                    Some(String(content)) => content
                    _ => fail("llm response missing message.content")
                  }
                _ => fail("llm response missing message")
              }
            _ => fail("llm response malformed choice")
          }
        _ => fail("llm response missing choices")
      }
    _ => fail("llm response not an object")
  }
}

///|
pub async fn OpenAiClient::complete(
  self : OpenAiClient,
  msgs : Array[Json],
) -> String {
  let url = self.base_url.trim(chars="/").to_owned() + "/chat/completions"
  let body : Json = {
    "model": self.model,
    "messages": msgs,
    "temperature": 0.0,
  }
  let headers : Map[String, String] = {
    "Content-Type": "application/json",
    "Authorization": "Bearer \{self.api_key}",
  }
  let (resp, data) = @http.post(url, body, headers~)
  if resp.code != 200 {
    let detail = data.text() catch { _ => "" }
    fail("llm http \{resp.code}: \{detail}")
  }
  content_of(data.json())
}

///|
pub fn OpenAiClient::model_name(self : OpenAiClient) -> String {
  self.model
}

///|
/// 从环境变量构造 client（缺 key → None）
/// MOONCAKE_LLM_BASE_URL（默认 https://api.openai.com/v1）
/// MOONCAKE_LLM_KEY / MOONCAKE_LLM_MODEL（默认 gpt-4o-mini）；
/// 兼容通用 API_KEY / Base_URL / Model 变量
pub fn client_from_env(getenv : (String) -> String?) -> OpenAiClient? {
  let key = match getenv("MOONCAKE_LLM_KEY") {
    Some(k) => k
    None =>
      match getenv("API_KEY") {
        Some(k) => k
        None => return None
      }
  }
  let base = match getenv("MOONCAKE_LLM_BASE_URL") {
    Some(b) => b
    None =>
      match getenv("Base_URL") {
        Some(b) => b
        None => "https://api.openai.com/v1"
      }
  }
  let model = match getenv("MOONCAKE_LLM_MODEL") {
    Some(m) => m
    None =>
      match getenv("Model") {
        Some(m) => m
        None => "gpt-4o-mini"
      }
  }
  Some({ base_url: base, api_key: key, model, })
}
