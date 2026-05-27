---
name: reduce-edr-detections
description: Use when reducing VirusTotal/EDR detection rates on compiled binaries — systematic A/B testing methodology with comprehensive PE structural analysis for identifying and eliminating ML classifier signals
allowed-tools: Read, Bash, Grep, Glob, Write, Edit, Agent, AskUserQuestion
---

# Reduce EDR Detections

**Systematic methodology for reducing VirusTotal and EDR detection rates on compiled binaries through comprehensive structural analysis, iterative A/B testing, and ML feature vector optimization.**

## When to Use

- VT detection rate is too high on compiled binaries
- ML classifiers (Wacatac, MalwareX-gen, ML.Attribute, Evo-gen, etc.) are flagging output
- Need to identify which binary attributes trigger detection
- After changes that may alter the PE/ELF structure
- Preparing binaries for deployment

## Prerequisites

- VT API key at `/path/to/vt_apikey`
- `pefile` and `lief` Python libraries — preferably in a venv (`python3 -m venv .venv && . .venv/bin/activate && pip install pefile lief`). On PEP 668 systems where you can't use a venv, add `--break-system-packages` to a system-wide `pip install`.
- PE Structural Analyzer script: see `references/pe-structural-analyzer.md`
- A vanilla binary from the same toolchain as your target (e.g., `GOOS=windows GOARCH=amd64 go build`)

## Core Principles

1. **Triage detection type before choosing remediation.** A YARA-style verdict (`Trojan/Win.Sliver.R774471`) and an ML verdict (`Wacatac.B!ml`, `ML.Attribute.HighConfidence`) require fundamentally different fixes. YARA matches fixed bytes — rename strings, swap imports, restructure sections. ML is a statistical classifier — renaming strings cannot defeat it, and trying often makes things worse. Label every hit before starting.
2. **Change ONE variable per experiment. 10–20 samples per test. Build control and variant in the same VT upload window.** ML models (especially Microsoft Wacatac.B!ml) retrain on approximately a daily cadence. A control batch built today and a variant built tomorrow is not a valid A/B test — half the observed delta will be model drift.
3. **Don't fight the toolchain identity.** Making a Go binary look less like Go creates inconsistencies that _increase_ detection — including renaming natural internal type names (e.g. `Allocator`, `Preamble`) that show up slightly over-represented in detected samples. That's likely `strings -n 6` extraction noise, not a real signal. See `references/experiment-categories.md`.
4. **Validate `strings -n 6` tokens against source before acting on them.** The `strings` tool glues adjacent in-memory strings together, producing tokens that look like meaningful symbols but are two unrelated strings concatenated across a buffer boundary. Grep the actual source tree to confirm before making a suspicious token a hypothesis.
5. **Camouflage, not concealment.** The goal is to give the classifier a believable answer to "what is this binary?" Mimicking the gopclntab symbol fingerprint of a single large real Go project (ghost profiling) consistently outperforms stripping, obfuscating, or padding. One coherent project; blending multiple produces a binary that matches no known software.
6. **VT is not ground truth, and there is an irreducible floor.** Microsoft's cloud ML is substantially more aggressive than the local Defender engine. A binary at 100% Wacatac on VirusTotal can be clean on a real endpoint. Once detection drops to roughly 15–25% (the stochastic floor near the ML threshold), further structural optimization rarely pays back.
7. **Measure everything.** Use the full PE structural analyzer before and after each change. Features you don't measure can't be correlated with detections.
8. **Compare against vanilla.** Always compare your binary against a clean vanilla binary from the same toolchain. The delta between them is your ML signal.
9. **ML classifiers use feature vectors, not individual features.** Compound anomalies accumulate — fix the ones that diverge most from the vanilla baseline.

## Phase 1: Establish Baseline

Build 10–20 identical-purpose samples. Upload all to VT and record per-engine results.

```bash
VT_KEY=$(cat /path/to/vt_apikey)
UPLOAD_URL=$(curl -s 'https://www.virustotal.com/api/v3/files/upload_url' \
  -H "x-apikey: $VT_KEY" | python3 -c "import sys,json; print(json.load(sys.stdin)['data'])")

for f in /tmp/samples/*.exe; do
  curl -s --request POST --url "$UPLOAD_URL" \
    --header "x-apikey: $VT_KEY" --form "file=@$f" > /dev/null
  sleep 16  # free-tier rate limit
done
sleep 300   # wait for analysis
sha256() { command -v sha256sum >/dev/null && sha256sum "$1" | cut -d' ' -f1 || shasum -a 256 "$1" | cut -d' ' -f1; }
for f in /tmp/samples/*.exe; do
  sha=$(sha256 "$f")
  curl -s "https://www.virustotal.com/api/v3/files/$sha" -H "x-apikey: $VT_KEY" | \
    python3 -c "import sys,json; d=json.load(sys.stdin); r=d['data']['attributes']['last_analysis_results']; dets={k:v for k,v in r.items() if v['category']=='malicious'}; print(f'{len(dets)}: {list(dets.keys())}')"
  sleep 4
done
```

Create a detection label file for the analyzer:

```json
{ "sample-01.exe": "clean", "sample-02.exe": "detected", ... }
```

## Phase 2: Comprehensive Structural Analysis

**Use the full PE Structural Analyzer** (see `references/pe-structural-analyzer.md`). It extracts 13 ML-relevant feature categories in one pass:

```bash
python3 pe_structural_analyzer.py /tmp/samples/ \
  --baseline /tmp/vanilla_go.exe \
  --detections /tmp/detections.json
```

Outputs: `/tmp/pe_analysis.json` (full), `/tmp/pe_analysis.csv` (flat), console clean-vs-detected comparison.

### Build the Vanilla Baseline

```bash
mkdir -p /tmp/vanilla && cd /tmp/vanilla && go mod init hello
printf 'package main\nimport ("fmt";"os")\nfunc main(){fmt.Println("hello");os.Exit(0)}' > main.go
GOOS=windows GOARCH=amd64 go build -o /tmp/vanilla_go.exe .
```

### Read the Baseline Delta

The analyzer prints every feature where your binary diverges from the vanilla baseline. Focus on:

- **Features ADDED** by your modifications (phantom sections, extra DLLs, resources)
- **Features AMPLIFIED** (BSS ratio from 6x to 208x, debug sections from 27% to 50%)
- **Features that CONTRADICT the toolchain identity** (wrong stack reserve for Go, linker version mismatch)

For the full taxonomy of what ML classifiers measure per feature category, see `references/pe-structural-features.md`.

### Clean vs. Detected Statistical Comparison

The analyzer outputs Cohen's d between clean and detected groups automatically. Guidance:

| Effect Size | Action |
|-------------|--------|
| d > 0.8 | Investigate immediately |
| d > 0.5 | Worth testing |
| d > 0.3 | Low priority |
| d < 0.3 | Noise — skip |

**With fewer than 5 clean samples, Cohen's d is unreliable.** When all samples are structurally identical and detection is stochastic, you need to shift the _entire_ feature vector, not individual features.

## Phase 3: Hypothesis Testing

For each signal from Phase 2:

1. **Form hypothesis**: "Removing X will move feature Y toward vanilla baseline"
2. **One change only**
3. **Build 10–20 samples**
4. **Run the analyzer** — verify the feature actually shifted before uploading
5. **Upload to VT**, wait, pull results
6. **Compare**: clean rate, anomaly score, vanilla delta
7. **Decision**: improved → keep, same/worse → revert

See `references/experiment-categories.md` for the safe vs. dangerous change taxonomy, and the experiment tracking table template.

### Testing Anti-patterns

- Don't overindex on small samples — n<5 correlations are noise
- Don't change multiple variables simultaneously
- Don't assume causation from correlation
- Don't fight the toolchain — a Go binary should look like Go, not MSVC

## Phase 4: Iterate

Repeat Phases 2–3 until: clean rate plateaus, remaining detections show no structural pattern, or feature vector matches vanilla baseline as closely as possible.

## Phase 5: Validate at Scale

Final validation with 20–30 samples of the real payload. Record as the release benchmark.

## Tracking Results

```
| Experiment | Change           | Samples | Clean% | Anomaly Score | Vanilla Delta | Keep? |
|-----------|-----------------|---------|--------|---------------|---------------|-------|
| Baseline  | —               | 20      | 15%    | 12            | 12 anomalies  | —     |
| Exp 1     | Remove .edata   | 20      | 20%    | 11            | 11 anomalies  | Yes   |
| Exp 2     | Patch linker v  | 20      | 5%     | 11 (incons.)  | 13 anomalies  | No    |
```

## Known Ineffective / Counterproductive Approaches

### Proven Counterproductive (WORSE detection)

- Patching linker version (Go 3.0 → MSVC 14.x) — toolchain inconsistency
- Adding fake Rich header to Go binary — inconsistent with Go's section layout
- XOR padding .text section — raises entropy to 6.99, triggers Bkav/Trapmine
- Block-shuffle padding .text — ML detects .text SIZE anomaly
- Stripping .symtab — Go always has it; absence is inconsistent with toolchain

### Proven Neutral (no effect)

- Code-level polymorphism (struct reorder, opaque predicates, AST transforms)
- Per-build filename randomization

### Proven Effective

- DLL pool pruning (remove netapi32, ole32, winhttp — unused import heuristic)
- Product name pruning (remove enterprise-sounding names that appear in malware datasets)
- Signing identity diversification — per-build random pick from a pool of plausible company names, description strings, and issuer suffixes eliminates stable YARA targets in the Authenticode blob
- Capping enriched DLLs at ≤3
- YARA signature kill (per-build renaming of wazero/WASM package paths and exported names)
- Ghost profiling — replacing a binary's gopclntab with harvested function/package names from a large real Go project. The classifier sees "legitimate infrastructure software" instead of a minimal Go runtime. Larger, coherent single-project profiles produce reliably lower detection rates; blending multiple projects typically makes detection worse.

## References

- [pe-structural-analyzer.md](references/pe-structural-analyzer.md) — Analyzer installation, usage, output format
- [pe-structural-features.md](references/pe-structural-features.md) — 13-category ML feature taxonomy
- [experiment-categories.md](references/experiment-categories.md) — Safe/dangerous change taxonomy, experiment tracking template

## Integration

### Called By
- Manual invocation when detection rates increase
- After ML model updates (re-test existing samples to detect regression)
- Before deploying new binary versions
