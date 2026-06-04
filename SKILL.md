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
10. **On-sensor EDR models are purely additive.** Reverse engineering of a major EDR's on-sensor ML model revealed 20 gradient-boosted trees with 1,000 binary features, ALL leaf weights positive (0.05–2.25) — the model only penalizes, never rewards. Zero triggered features = score 0.0 = always passes. There is no "benign bonus" for looking legitimate — only penalties for looking malicious. Fewer anomalies = lower score = less detection.

## On-Sensor EDR Model Intelligence

Reverse engineering of a major EDR vendor's kernel driver and on-sensor ML model produced verified intelligence about how the static analysis pipeline works. This informs which PE features to prioritize.

### Model Architecture

- **20 gradient-boosted decision trees**, 8,976 total binary-feature nodes
- **1,000-dimensional binary feature vector** (present/absent per indicator)
- **Purely additive scoring** — all 514 non-trivial leaf weights are positive (0.05–2.25)
- **Binary feature model** — features are primarily binary (is indicator X set?), though ~380 float64 split values exist in the model data for computed features like entropy scores
- 2 sub-models (likely benign vs malicious binary classifiers)

### EDR Static Analysis Passes (Verified)

The EDR kernel driver runs these passes on every file write / process creation:

| Pass | Codes | Feature range | What it checks |
|------|-------|--------------|----------------|
| **BM** (Binary Metadata) | BM00–BM37 | 205–242 | PE headers, sections, data directories — presence/absence checks |
| **Re** (Recognition) | Re01–Re43 | 69–111 | **Import table capability detection** — 43 API categories |
| **BR** (Binary Recognition) | BR00–BR61 | 259–356 | Byte pattern signatures from signature update files (updated daily) |
| **CR** (Content Recognition) | CR00–CR18 | 357–374 | Multi-pattern content scanning (Aho-Corasick style) |
| **cC** (Content Category) | cC01–cC34 | 375–408 | Content type classification (native PE, .NET, script, packer) |
| **Te** (Text Analysis) | Te00–Te22 | 124–125+ | String content: URLs, IPs, file paths, encoded strings |
| **FPE** (Feature PE) | FPE0–FPE2 | 950–952 | PE entropy analysis, section anomalies, overlay data |
| **Pes** (PE Sections) | Pes1–Pes3 | 121–123 | High-entropy executable sections, non-standard names |
| **Fs** (Filesystem) | Fs01–FsHl | 66, 112–120 | File location, attributes — **FsHl is rank #4 in model** |
| **SM** (Static Model) | SM00–SM11 | 250–258 | ML model sub-scores (the model evaluating itself) |

### Import Capability Detection — Ranked by Model Weight

The Re pass checks the **import table only** (IAT/ILT). APIs resolved dynamically via GetProcAddress or direct syscalls are invisible to this pass.

| Re code | Model rank | APIs detected | Go binary relevance |
|---------|-----------|---------------|---------------------|
| Re07 | **#3** | CreateProcess, ShellExecute, WinExec | Go imports CreateProcess via kernel32 |
| Re27 | **#6** | GetThreadContext, SetThreadContext | Not in standard Go |
| Re40 | **#7** | CreateMutex, OpenMutex | **Go's sync package may import** |
| ReUM | **#15** | High import table diversity score | **Go binaries have many imports** |
| Re01 | **#16** | CreateToolhelp32Snapshot, EnumProcesses | Depends on Go code |
| Re03 | **#17** | SetWindowsHookEx, GetAsyncKeyState | Not in standard Go |
| Re17 | **#19** | VirtualAllocEx | Not in standard Go |
| Re18 | **#20** | CreateRemoteThread | Not in standard Go |

**Key for Go binaries**: Re07 (CreateProcess) and ReUM (import breadth) are the highest-impact controllable features. Go's runtime imports many DLLs by default — each additional enriched DLL contributes to the ReUM score. Pruning unused DLL imports is high-leverage.

### BM Pass — What Triggers PE Metadata Indicators

BM indicators fire based on **presence/absence** of PE header fields (zero/non-zero checks):

| BM code | Fires when | Go binary impact |
|---------|-----------|-----------------|
| BM12 | Exactly 1 PE section | Not applicable — Go has 16+ sections |
| BM34 | Exactly 1 import DLL | Not applicable — Go imports multiple |
| BM11 | Debug directory present | Go vanilla has none — adding one is inconsistent |
| BM16 | Non-standard section names (4 checks) | **Go's numeric sections (/4, /19) trigger this** |
| BM22 | Certificate/Security directory present | Signing adds this — **positive for Go builds** |
| BM07–BM10 | Data directory entries (Import, Export, Resource, Exception) present | Standard Go has Import only |

**Key insight**: BM12 and BM34 flag minimal PEs. Go binaries are naturally safe here. BM16 fires on Go's numeric section names — this is **expected for the toolchain** and not worth fighting (Principle 3).

### FPE Pass — Entropy Thresholds

| Code | Meaning | Threshold (inferred from macOS equivalent) |
|------|---------|---------------------------------------------|
| FPE0 | High-entropy code section | Likely ~7.0 for .text (Go vanilla: 6.12, modified: 6.99) |
| FPE1 | Section attribute anomalies (W+X) | Any section with both write AND execute flags |
| FPE2 | Overlay/appended data | Data after last PE section |

**Key for Go binaries**: A Go binary with embedded WASM/compressed data in debug-like sections pushes file entropy from 6.85 to 7.44. If .text entropy reaches 7.0+, FPE0 fires. XOR padding .text to 6.99 is right at the threshold — avoid.

### Cloud Prediction (Second Tier)

The EDR also sends the **first 10,000 bytes** of the PE to a cloud ML model for a second opinion. This means:
- PE headers + first section content are deeply analyzed in the cloud
- Content beyond 10KB is invisible to the cloud tier
- Results are cached (LRU, 10 entries) — first scan matters most
- Cloud model can be more aggressive than on-sensor model

**Implication for Go binaries**: Go PE headers are in the first 10KB. Ensure header fields are maximally consistent with vanilla Go in this region.

**Note**: The pass names (BM, Re, BR, CR, cC, Te, FPE, Pes, Fs, SM) are internal indicator code prefixes extracted from the EDR kernel driver. They are referenced in the analyzer output and experiment tracking.

### What Static Analysis Cannot See (Verified Blind Spots)

1. **Dynamic API resolution** — GetProcAddress calls are invisible to the import analysis pass
2. **Section content beyond byte patterns** — If your content doesn't match a pattern category, it's opaque
3. **Runtime behavior from static scan** — The static model cannot predict what code will DO
4. **Files > 10KB in the cloud** — Only the first 10KB goes to the cloud model

### WARNING: Static Evasion Is Not Sufficient

**Passing the static ML model only gets the binary to START executing.** The EDR kernel driver also registers runtime callbacks that catch operations regardless of how they're invoked:

| Callback | Monitors | Evaded by syscalls? |
|----------|---------|:-------------------:|
| PsSetCreateProcessNotifyRoutineEx | Every process creation | **No** |
| PsSetCreateThreadNotifyRoutine | Every thread creation | **No** |
| PsSetLoadImageNotifyRoutine | Every DLL/EXE load | **No** |
| ObRegisterCallbacks | Handle operations (OpenProcess) | **No** |
| CmRegisterCallbackEx | All registry operations | **No** |
| FltRegisterFilter | All file I/O | **No** |

**In-memory pattern scanning** (a user-mode servlet) also scans process memory after execution, catching decrypted payloads, reflective DLLs, and C2 beacons.

**AMSI** intercepts PowerShell, VBScript, JScript, and .NET content at the kernel level.

These checks happen AT RUNTIME — after the static model has already passed or failed the binary. The static model optimization in this skill addresses the FIRST gate only. Runtime behavioral correlation is a separate detection layer that this skill does not address.

### Alternative Execution Models (Bypass Static Analysis Entirely)

Non-PE execution models bypass the PE-centric static analysis pipeline completely:

| Model | Static model | AMSI | Runtime callbacks |
|-------|:-----------:|:----:|:-----------------:|
| Python/Lua/Ruby scripts | Bypassed | **Not covered** | Actions still visible |
| WASM runtime (wasmtime) | Bypassed | Bypassed | Actions still visible |
| .NET CLR in-process hosting | Bypassed | Likely bypassed | Actions still visible |
| Raw shellcode (VirtualAlloc) | Bypassed | Bypassed | Actions still visible |

If detection rates cannot be reduced sufficiently through PE optimization, consider whether the payload can be restructured as a non-PE execution model where the static analysis pipeline has no PE to analyze.

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

- DLL pool pruning (remove netapi32, ole32, winhttp — unused import heuristic). **EDR verified**: each extra DLL contributes to ReUM (rank #15 in model).
- Product name pruning (remove enterprise-sounding names that appear in malware datasets)
- Signing identity diversification — per-build random pick from a pool of plausible company names, description strings, and issuer suffixes eliminates stable YARA targets in the Authenticode blob. **EDR verified**: BM22 fires when certificate directory is present (positive — signing is good).
- Capping enriched DLLs at ≤3. **EDR verified**: ReUM measures import table diversity; fewer DLLs = lower ReUM contribution.
- YARA signature kill (per-build renaming of wazero/WASM package paths and exported names). **EDR verified**: BR pass uses 98 byte-pattern categories from daily-updated signature update files.
- Ghost profiling — replacing a binary's gopclntab with harvested function/package names from a large real Go project. The classifier sees "legitimate infrastructure software" instead of a minimal Go runtime. Larger, coherent single-project profiles produce reliably lower detection rates; blending multiple projects typically makes detection worse.
- **Keeping .text entropy below 7.0** — EDR's FPE0 indicator fires on high-entropy code sections. Go vanilla .text is ~6.12; XOR padding pushes to 6.99 (borderline). Stay below 7.0.
- **File placement matters** — EDR's FsHl (rank #4 in model) heavily penalizes files in suspicious locations (%TEMP%, Downloads, %APPDATA%). Deploy to standard program directories.

### EDR Model Insights (Verified by Reverse Engineering)

- **The model is purely additive** — zero features triggered = score 0.0 = always passes. There is no "benign bonus." Every structural anomaly removed lowers the score.
- **Leaf weights are bimodal: 0.05 or 2.0+.** Non-trivial leaves are either "confident bad" (weight ~2.0–2.25, 92%) or "not sure" (weight ~0.05, 8%). Untriggered features produce zero-weight contributions. There are NO moderate signals.
- **Go vanilla is at the detection boundary.** A vanilla Go binary triggers 9 Re codes, causing multiple trees to reach strong leaves. Adding payload-specific indicators pushes the score higher. **Each additional triggered indicator category moves the score further into detection range.** The relationship is approximate — trees evaluate feature combinations, not single indicators.
- **Import pruning has outsized impact.** An implant adding VirtualAllocEx + CreateRemoteThread + OpenProcess (Re17+Re18+Re26) contributes significant additional score. Resolving these dynamically (GetProcAddress) or via syscalls removes their contribution.
- **Import table is the #1 controllable attack surface** — Re07 (CreateProcess, rank #3), Re40 (CreateMutex, rank #7), ReUM (breadth, rank #15) are the most impactful features you can control.
- **Sensor context features dominate** (ranks #1, #2) — CSpc and SCtb are internal sensor state you cannot control. **FsHl (rank #4) is partially controllable** — it penalizes files in suspicious locations (%TEMP%, Downloads, %APPDATA%). Deploy to standard program directories to avoid triggering it.
- **The cloud model sees only the first 10KB** of the PE. Structural headers are in this window — ensure they are maximally vanilla. Payload content beyond 10KB is invisible to the cloud tier.
- **BM12 flags single-section PEs** — Go binaries are safe here (16+ sections). **BM34 flags single-import-DLL PEs** — vanilla Go may trigger this (imports kernel32 only). Enriched builds with additional DLLs avoid BM34, but adding too many triggers ReUM. The balance: 2–3 DLLs.
- **Signature patterns (BR pass) update daily.** Byte-pattern evasion is transient. Structural evasion (reducing the feature vector toward vanilla baseline) is durable.

### Go Runtime Unavoidable Baseline

A vanilla Go binary triggers these Re codes regardless of what your code does:

| Re | Importance | Go runtime API | Removable? |
|----|-----------|---------------|------------|
| Re27 | **25** | GetThreadContext/SetThreadContext (goroutines) | **No** |
| Re01 | **22** | CreateToolhelp32Snapshot (runtime) | **No** |
| ReTe | **21** | GetStdHandle (console I/O) | No |
| Re05 | 0 | OpenProcessToken | Maybe — if not needed |
| Re19 | 0 | LoadLibraryExW | No |
| Re25 | 0 | TerminateProcess | No |
| Re28 | 0 | SuspendThread/ResumeThread (goroutines) | No |
| Re38 | 0 | VirtualProtect | No |
| ReGq | 0 | GetQueuedCompletionStatusEx (IOCP) | No |

**Total Go vanilla importance: 68** (9 codes, ~9 strong trees)

Each payload-specific import (Re17 VirtualAllocEx, Re18 CreateRemoteThread, Re26 OpenProcess, Re09 ReadProcessMemory) adds another strong tree. The optimization target: keep total triggered Re codes as close to the vanilla 9 as possible.

## References

- [pe-structural-analyzer.md](references/pe-structural-analyzer.md) — Analyzer installation, usage, output format
- [pe-structural-features.md](references/pe-structural-features.md) — 13-category ML feature taxonomy with verified EDR model weights
- [experiment-categories.md](references/experiment-categories.md) — Safe/dangerous change taxonomy, experiment tracking template
- [edr-model-intelligence.md](references/edr-model-intelligence.md) — Verified on-sensor EDR model architecture, feature vector layout, import capability mapping

## Integration

### Called By
- Manual invocation when detection rates increase
- After ML model updates (re-test existing samples to detect regression)
- Before deploying new binary versions
