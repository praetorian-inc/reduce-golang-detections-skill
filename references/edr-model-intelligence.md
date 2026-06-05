# On-Sensor EDR Model Intelligence

Verified findings from reverse engineering a major EDR vendor's kernel driver and on-sensor
ML model. Source: kernel driver, model binary, user-mode service.

## On-Sensor ML Model

- 20 gradient-boosted trees, 8,976 binary-feature nodes
- 1,000-dimensional binary feature vector (present/absent)
- ~9,100 leaf weights, ALL positive (0.05–2.25) — purely additive
- 2 sub-models (benign/malicious)
- Model stored in .data section of a kernel-mode PE

## Feature Vector Layout

| Range | Source | Count | Purpose |
|-------|--------|------:|---------|
| 69–111 | Re01–Re43 | 43 | Import capability detection |
| 121–123 | Pes1–Pes3 | 3 | PE section indicators |
| 124–125 | Tes1–Tes2 | 2 | Text section features |
| 205–242 | BM00–BM37 | 38 | PE header metadata |
| 259–356 | BR00–BR61 | 98 | Byte pattern signatures |
| 357–374 | CR00–CR18 | 18 | Content recognition |
| 375–408 | cC01–cC34 | 34 | Content categories |
| 950–952 | FPE0–FPE2 | 3 | PE entropy/structure |

## Top 20 Model Features by Importance

| Rank | Feature | Code | Refs | Controllable? |
|-----:|--------:|------|-----:|:--------------|
| 1 | 165 | CSpc | 35 | No (sensor) |
| 2 | 167 | SCtb | 35 | No (sensor) |
| 3 | **75** | **Re07** | **27** | **Yes — import: CreateProcess** |
| 4 | 120 | FsHl | 26 | Partial — file location |
| 5 | 64 | AcBu | 25 | No |
| 6 | **95** | **Re27** | **25** | **Yes — import: GetThreadContext** |
| 7 | **108** | **Re40** | **25** | **Yes — import: CreateMutex** |
| 8 | 112 | Fs02 | 25 | No |
| 9–11 | 166–169 | SSsq/SCst/SCpi | 23 | No (sensor) |
| 12 | **124** | **Tes1** | **23** | **Yes — text section** |
| 15 | **68** | **ReUM** | **22** | **Yes — import diversity** |
| 16 | **69** | **Re01** | **22** | **Yes — import: process enum** |
| 17 | **71** | **Re03** | **22** | **Yes — import: user input** |
| 19 | **85** | **Re17** | **21** | **Yes — import: VirtualAllocEx** |
| 20 | **86** | **Re18** | **21** | **Yes — import: CreateRemoteThread** |

## Import Capability Categories (Re01–Re43)

The import analysis pass scans the IAT/ILT only. Dynamic resolution is invisible.

| Re | APIs | Go relevance |
|----|------|-------------|
| Re07 (rank #3) | CreateProcess, ShellExecute, WinExec | Go runtime imports CreateProcessW |
| Re40 (rank #7) | CreateMutex, OpenMutex | Go sync may import |
| ReUM (rank #15) | Import table diversity | Go has many DLLs by default |
| Re19 | LoadLibrary, LdrLoadDll | Go runtime uses LoadLibraryExW |
| Re25 | TerminateProcess | Go runtime imports this |
| Re38 | VirtualProtect | Go runtime uses this |

## BM Pass — Exact Conditions

| Code | Feature | Condition | Go impact |
|------|--------:|-----------|-----------|
| BM00 | 205 | PE signature valid | Always fires (good) |
| BM01 | 206 | NumberOfSections > 0 | Go has 16+ sections |
| BM12 | 217 | Exactly 1 section | Go safe — many sections |
| BM16 | 221 | Non-standard section names | Go numeric names (/4 /19) trigger this |
| BM22 | 227 | Certificate directory present | Signing sets this (positive) |
| BM34 | 239 | Exactly 1 import DLL | Go safe — multiple DLLs |

## FPE Pass — Entropy Analysis

| Code | Feature | Meaning | Threshold (inferred) |
|------|--------:|---------|---------------------|
| FPE0 | 950 | High-entropy code section | ~7.0 for .text |
| FPE1 | 951 | Section attribute anomalies (W+X) | Any write+execute |
| FPE2 | 952 | Overlay/appended data | Data past last section |

Go vanilla .text entropy: ~6.12. Modified builds with XOR padding: ~6.99 (borderline).
Stay below 7.0.

## Cloud Prediction (Second Tier)

- First 10,000 bytes of PE sent to cloud for second-tier ML
- Cloud model may be more aggressive than on-sensor
- Results cached in LRU (10 entries)
- Content beyond 10KB boundary invisible to cloud

## Signature Updates (BR Pass)

- 98 byte-pattern categories in BR00–BR61
- Patterns loaded from encrypted signature update files
- Updated daily/hourly — byte-pattern evasion is transient
- Structural evasion (reducing feature vector) is durable

## Model Scoring Math

### Leaf Weight Distribution (Bimodal)

```
[0.05, 0.10):   41 weights (  8%) — "not sure" leaves (minimum weight 0.05)
[0.10, 2.00):    0 weights (  0%) — NOTHING IN BETWEEN
[2.00, 2.26):  473 weights ( 92%) — "confident bad" leaves
```

The non-trivial leaf weights are bimodal. Trees also have zero-weight leaves (default
path when no indicator matched) — a feature that is NOT set produces a 0.0 contribution.

### Score Calculation

```
Score = sum of 20 leaf weights (one leaf per tree)

Zero features triggered: score 0.0   (all trees reach default zero-weight leaves)
All trees hit weak leaves: score ~1.0  (20 × 0.05)
All trees at max: score ~45.0          (20 × 2.25)
```

**Score 0.0 = always passes.** Zero triggered indicators = zero model contribution.

### Estimated Detection Threshold

The relationship between triggered indicators and score is approximate — each tree
evaluates combinations of features (2–10 per path), not single indicators. But as
a rough model:

| Triggered indicators | Approx score | Detection? |
|---------------------:|-------------|------------|
| 0 | 0.0 | Clean |
| 5–8 | ~5–16 | Likely clean |
| 9 (Go vanilla) | ~10–20 | **Borderline** |
| 12–15 | ~15–30 | **LIKELY DETECTION THRESHOLD** |
| 16+ | ~20–45 | Detected |

A vanilla Go binary triggers 9 Re codes, which causes multiple trees to reach
"confident bad" leaves. Adding payload-specific indicators pushes more trees to
strong leaves. **Reducing total triggered indicators brings the score back toward
the clean range.**

**Important**: These are estimates. Each tree evaluates feature COMBINATIONS, not
single features. Two binaries with the same indicator count but different combinations
may score differently.

## Go Runtime → Re Code Mapping (Vanilla Baseline)

These Re indicators fire for a **vanilla Go binary** (unavoidable baseline):

| Re code | Importance | Triggered by | Required by Go runtime? |
|---------|-----------|--------------|------------------------|
| Re27 | **25** | GetThreadContext, SetThreadContext | **YES** — goroutine scheduling |
| Re01 | **22** | CreateToolhelp32Snapshot, Process32First/Next | **YES** — runtime process inspection |
| ReTe | **21** | GetStdHandle | **YES** — console I/O |
| Re05 | 0 | OpenProcessToken | Likely — token checks |
| Re19 | 0 | LoadLibraryExW | **YES** — dynamic loading |
| Re25 | 0 | TerminateProcess | **YES** — exit handling |
| Re28 | 0 | SuspendThread, ResumeThread | **YES** — goroutine scheduling |
| Re38 | 0 | VirtualProtect | **YES** — memory management |
| ReGq | 0 | GetQueuedCompletionStatusEx | **YES** — I/O completion ports |

**Total baseline Re importance: 68** (from 9 codes, mostly low-weight)

### Additional Re Codes from Payload Features

Each of these adds ~2.0 to the model score per triggered tree:

| Re code | Importance | APIs | Typical implant usage |
|---------|-----------|------|----------------------|
| Re17 | **21** | VirtualAllocEx | Cross-process memory allocation |
| Re18 | **21** | CreateRemoteThread | Thread injection |
| Re26 | **21** | OpenProcess | Process manipulation |
| Re09 | **21** | ReadProcessMemory | Memory reading |
| Re07 | **27** | CreateProcess, ShellExecute | Command execution |
| Re40 | **25** | CreateMutex | Single-instance check |
| Re03 | **22** | SetWindowsHookEx | Keylogging/hooking |

**Each additional Re code from this list pushes the score ~2.0 points higher.**
An implant adding Re17+Re18+Re26 adds ~6.0 to the score — potentially crossing
from borderline (score ~20) to detected (score ~26).

## BS (Binary Static) Feature Codes

90 Binary Static indicators at model features 494–583. These fire based on
the binary's structural properties (not imports). The specific conditions are
loaded from signature update files and update frequently.

Notable: BS codes are the second-largest indicator category (after BR byte patterns)
but their model importance is generally lower than Re codes because they occupy
features 494–583 which are outside the model's most-referenced range.

## Key Implications for Go Binary Optimization

1. **The model only penalizes, never rewards.** Fewer anomalies = lower score.
2. **Go vanilla is RIGHT at the detection boundary** (~9 strong trees out of 20).
   Payload features push it over. Every indicator removed moves you back toward clean.
3. **Import table is the #1 controllable surface.** Prune DLLs aggressively.
   Each removed Re code saves ~2.0 model score points.
4. **Don't fight the toolchain.** The BM pass checks PE metadata presence/absence — Go's
   natural structure (16+ sections, numeric names, no Rich header) is consistent.
5. **File location matters.** FsHl (rank #4) penalizes %TEMP%/Downloads paths.
6. **Keep .text entropy < 7.0.** FPE0 fires above this threshold.
7. **Cloud sees first 10KB only.** Keep headers vanilla in this window.
8. **The model has NO moderate signals.** Each tree is either "confident bad" or
   "not sure." There is no gradual scoring — indicators are binary on/off switches
   that flip trees between 0.05 and 2.0+ contribution.
