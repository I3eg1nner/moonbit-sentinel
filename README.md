# moonbit-sentinel

[![CI](https://github.com/I3eg1nner/moonbit-sentinel/actions/workflows/ci.yml/badge.svg)](https://github.com/I3eg1nner/moonbit-sentinel/actions/workflows/ci.yml)

Static supply-chain security detector for [mooncakes.io](https://mooncakes.io) packages, written in MoonBit.

It statically analyzes an extracted package directory — manifests, pre-build hooks, source files, and bundled artifacts — for the behaviors that distinguish **malicious packages** from merely messy ones: typo-squatting of popular names, official-namespace impersonation, install-time command chains, network exfiltration to hardcoded endpoints, credential access, obfuscated payloads, and dropped binaries. Every scan yields a risk score and a verdict: **Malicious / Suspicious / Clean**.

## What it detects

| Family | Rules | Highlights |
|---|---|---|
| Source | S01–S08 | raw-IP/hardcoded exfil endpoints, credential paths, shell execution, **base64 payload decoding with content inspection** (urls / shells / downloaders → Critical), env sniffing, persistence writes |
| Hooks | S06 | pre-build command-chain classification: pipe-to-shell, command substitution, base64-decode-exec, reverse-shell indicators |
| Artifacts | S10 | binary magic detection (ELF/PE/Mach-O), **disguised executables** (benign extension + binary magic), **embedded downloader/reverse-shell strings inside binaries**, nested archives, shebang scripts |
| Combo | S99 | network + credential/obfuscation in the same file escalates to Critical |

Detection is purely behavioral: metadata identity rules (name/author/repo heuristics) were removed after real-world tuning showed they produced every false positive while contributing no unique malicious signal — see the canaries for what the behavioral engine catches on its own.

Run `moonbit-sentinel rules` for the full catalog with triggers, examples, and mitigations. Test and demo fixtures are downweighted automatically, and known data-table shapes (tokenizer vocabularies) are guarded against false positives — the engine was tuned against a full crawl of the mooncakes.io registry.

## Build

Requires the MoonBit toolchain (`moon`) ≥ 0.10.14.

```bash
moon check
moon test
moon build --target native --release
```

The binary lands at `_build/native/release/build/cmd/main/main.exe`.

## Usage

```bash
ENGINE=$(find _build/native/release -type f -executable | head -1)

# scan an extracted package directory
"$ENGINE" scan /tmp/pkg --module owner/name --version 0.1.0

# outputs: human (default) | json | sarif | md
"$ENGINE" scan /tmp/pkg --json
"$ENGINE" scan /tmp/pkg --format sarif > report.sarif
"$ENGINE" scan /tmp/pkg --format md >> "$GITHUB_STEP_SUMMARY"

# explain the score, rule by rule
"$ENGINE" scan /tmp/pkg --explain

# CI gate: non-zero exit when the verdict reaches the threshold
"$ENGINE" scan /tmp/pkg --fail-on malicious

# rule catalog
"$ENGINE" rules
```

Options:

| Flag | Meaning |
|---|---|
| `--module m` | registry module name (enables authoritative-name checks) |
| `--version v` | package version recorded in the report |
| `--hotlist file` | popular-module list (default: builtin top-100 snapshot) |
| `--min-severity s` | `low\|medium\|high\|critical` filter |
| `--format s` | `human\|json\|sarif\|md` |
| `--explain` | print the score breakdown |
| `--fail-on s` | `suspicious\|malicious` CI exit gate |

## LLM adjudication (optional)

`--llm` adds a single-call LLM adjudication on top of the deterministic verdict — a minimal agent, no tool loops. The model receives the engine verdict, the findings, and the rule-catalog entries for the rules that fired (budgeted evidence, never the whole package), and must answer one JSON object: `{verdict, confidence, rationale}`. One self-correcting retry on malformed JSON. The result is **advisory** — it is printed alongside and merged into `--format json` output as an `assessment` field, but never overrides the engine verdict. Every model interaction passes through a hard `CallBudget` (cap: **20 calls** per scan, enforced in the client; the current flow uses at most 2), so the agent stays minimal by construction even if the orchestration evolves.

```bash
export MOONCAKE_LLM_KEY=...            # or API_KEY
export MOONCAKE_LLM_BASE_URL=...       # OpenAI-compatible /v1 endpoint (or Base_URL)
export MOONCAKE_LLM_MODEL=...          # e.g. GLM-5.3-Flash (or Model)
"$ENGINE" scan /tmp/pkg --llm --explain
```

Why: purely behavioral rules cannot tell a credential-reading CI runner from a stealer — the LLM layer adjudicates exactly these borderline cases (e.g. it upholds `Malicious` on decode-to-exfiltrate combos while correctly clearing runner-style packages the engine scores just over the line).

## Try it now

```bash
./examples/scan_canaries.sh
```

Scans the bundled canaries offline: `typo_malicious` → Malicious, `benign_http` → Clean. See `examples/README.md`.

## CI

`.github/workflows/ci.yml` runs check → test → wasm build → native build → a self-scan dogfood step on every push/PR. To gate your own package CI:

```yaml
- run: |
    git clone --depth 1 https://github.com/I3eg1nner/moonbit-sentinel /tmp/auditor
    cd /tmp/auditor && moon build --target native --release
    ENGINE=$(find _build/native/release -type f -executable | head -1)
    "$ENGINE" scan "$PKG_DIR" --module "$PKG_NAME" --fail-on suspicious
```

## Reproducing the registry audit

The canary fixtures (`canaries/`) pin the scoring model end-to-end: `moon test` asserts each canary's verdict. The false-positive hardening (same-author exemption, data-table guards, test/demo downweighting) is regression-tested against patterns distilled from a full mooncakes.io crawl.

## Development

```bash
moon test          # 111 tests: unit + canary e2e
moon fmt           # format
moon info          # refresh pkg.generated.mbti (public API surface)
```

Layout: `engine/` (finding model, matchers, rule catalog) · `metadata/` (manifest parsing, M-rules) · `source/` (S-rules) · `engine/scan/` (orchestrator) · `score/` · `report/` (json/human/sarif/markdown) · `cmd/main/` (CLI).

## Publish to mooncakes.io

1. `moon.mod` 的 `name` 已是 `minie135/moonbit-sentinel`。
2. `moon login` 后执行 `moon publish`。
## License

Apache-2.0. The scan engine is original work; canary fixtures are hand-written samples.
