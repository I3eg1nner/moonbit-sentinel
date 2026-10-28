# Examples

## scan_canaries.sh

Builds the auditor and runs it against the bundled canary fixtures:

- `canaries/typo_malicious` — typo-squat of `moonbitlang/async`, hardcoded
  exfil IP, credential read. Expected verdict **Malicious**.
- `canaries/benign_http` — ordinary HTTP client usage. Expected verdict
  **Clean**.

```bash
./examples/scan_canaries.sh
```

No network access required; the fixtures live in this repository.

## Scan a real package

```bash
moon build --target native --release
ENGINE=$(find _build/native/release -type f -executable | head -1)
mkdir -p /tmp/pkg && unzip some-package.zip -d /tmp/pkg
"$ENGINE" scan /tmp/pkg --module owner/name --version 0.1.0 --explain
```
