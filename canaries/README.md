# Canary fixtures

Fixed sample packages pinned by `engine/scan/e2e_test.mbt`; each asserts a
verdict through the full `run_scan` pipeline (walk → source rules → scoring).

- `behavior_exfil` (`eviluser/behavior_exfil`): credential read + raw-IP
  exfil POST in one file (S01+S02 → S99) plus an obfuscated blob decoding to
  a downloader URL (S04 decoded payload) → 70, Malicious.
- `prebuild_dropper` (`eviluser/build-helper`): `pre-build` hook that pipes
  `curl` into `sh`, plus a source-level `@shell.Cmd("curl", ...)` → S06 + S03
  + S01 = 60, Malicious.
- `obfuscated_exfil` (`eviluser/obfz`): base64 blob decoding to a downloader
  URL → S04 decoded payload Critical = 25, Suspicious.
- `dropped_binary` (`eviluser/dropped_binary`): an ELF executable disguised
  as `assets/logo.png` with an embedded `curl http://` downloader string →
  S10 (magic + disguise + embedded downloader, collapsed to Critical) = 25,
  Suspicious.
- `benign_http` (`goodorg/http-client-demo`): ordinary HTTPS demo client →
  risk 0, Clean (zero false positives).

These directories are committed fixtures, not runtime artifacts; each has its
own `moon.mod` so the scanner sees a realistic package layout.
