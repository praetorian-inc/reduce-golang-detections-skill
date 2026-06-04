# PE Structural Features: ML Classifier Taxonomy

What AV ML engines measure, organized by feature category. Use this to understand
which features your changes affect and what the classifier sees.

## How ML Classifiers Work

Engines like Symantec ML.Attribute.HighConfidence and AhnLab MalwareX-gen extract a
~200-2000 dimensional feature vector from each PE binary, then run a trained classifier.
**No single feature triggers detection — the full vector is scored together.**

This means:
- Individual "anomalies" may not matter if everything else looks clean
- Multiple small anomalies that point in the same direction are detected with high confidence
- Fighting the toolchain identity adds inconsistency signals that raise the score

## Verified On-Sensor Model Architecture

Reverse engineering of a major EDR vendor's kernel driver and on-sensor ML model
produced verified feature weights:

- **1,000-dimensional binary feature vector** — each feature is binary (present/absent)
- **20 gradient-boosted trees**, 8,976 nodes, ~9,100 leaf weights
- **Purely additive scoring** — ALL leaf weights positive (0.05–2.25), zero negative
- **10 static analysis passes** run on every file at kernel level:
  BM (PE headers, 38 features), Re (imports, 43 features), BR (byte patterns, 98 features),
  CR (content patterns, 18), cC (content category, 34), Te (strings, 24), FPE (entropy, 3),
  Pes (sections, 3), Fs (filesystem, 11), AS (aggregates, 13)
- **BM pass uses zero/non-zero checks** — PE fields checked for presence, not value
- **BM12 flags single-section PEs, BM34 flags single-import PEs** — Go safe here
- **ReUM (import breadth) is rank #15** — import table diversity is penalized
- **FPE0 entropy threshold** inferred ~7.0 for code sections (macOS equivalent: 7.0–7.8)
- **Cloud model receives first 10KB only** — content beyond that boundary is invisible
- **Kernel driver does NOT import ZwProtectVirtualMemory** — memory protection changes invisible
- **Signature patterns (BR pass) update daily** — byte pattern evasion is transient

## Feature Category Reference

### 1. Header Fields (High ML Weight)

| Feature | What ML Sees | Notes |
|---------|-------------|-------|
| `MajorLinkerVersion` | 3 = Go, 14 = MSVC, 2 = MinGW | Strong toolchain fingerprint |
| `TimeDateStamp` | 0 = Go/reproducible builds | Epoch-zero is an anomaly but consistent with Go |
| `SizeOfStackReserve` | Go default: 0x200000 | Changing from default adds inconsistency |
| `DllCharacteristics` | 0x8160 = Go standard | Fine |
| `CheckSum` | 0 = no checksum, nonzero = computed | We compute it — slightly inconsistent with vanilla Go |
| Rich header | Absent in Go/Rust/MinGW | Absence correlates with non-MSVC toolchains |

**Key principle**: Do NOT patch header fields to look like a different toolchain. The section
layout, import style, and string patterns still scream Go. Inconsistency = higher score.

### 2. Section Table (Highest ML Weight)

| Feature | Vanilla Go | Modified Build | ML Impact |
|---------|-----------|-----------------|-----------|
| Section count | 16 | 18 (+.rsrc, .edata) | Medium |
| .data BSS ratio (virt/raw) | 6.4x | 208x | **Very High** |
| Debug-like sections % | 27% | 50% | **High** |
| Max section entropy | 7.998 | 7.999 | Low (both near max) |
| High-entropy section count | 6 | 7 | Low |
| Numeric section names (/4, /19…) | 8 | 8 (same) | Low |
| .symtab present | Yes | Yes (4x larger) | Medium |
| Phantom .edata (section + no export dir) | No | Yes | Medium |

**The 208x BSS ratio is the single largest structural anomaly.** It comes from Sliver's
global variable allocation. Vanilla Go hello-world has 6.4x. This is load-bearing — cannot
be easily changed without modifying the linker.

### 3. Import Table (High ML Weight — Verified)

| Feature | Vanilla Go | Modified Build | On-sensor EDR feature |
|---------|-----------|-----------------|---------------------|
| DLL count | 1 | 4 | **ReUM (rank #15)** — diversity penalized |
| Total imports | 47 | 53 | Contributes to ReUM score |
| GetProcAddress present | Yes | Yes | Re19 (MayLoadDynamicLibrary) |
| LoadLibraryExW present | Yes | Yes (duplicated) | Re19 |
| CreateProcess* present | Via Go runtime | Via Go runtime | **Re07 (rank #3)** — highest-weight import |
| CreateMutex* present | If sync used | If sync used | **Re40 (rank #7)** — surprisingly high weight |

**The EDR's import analysis pass checks the IAT/ILT only.** APIs resolved via GetProcAddress
at runtime are invisible. The model has 43 import category indicators (Re01–Re43) plus ReUM (breadth).

**Import pruning priority by verified model weight:**
1. Remove any import triggering Re07 (CreateProcess) if not needed — rank #3
2. Remove any import triggering Re40 (CreateMutex) — rank #7, use events instead
3. Minimize total DLL count — ReUM (rank #15) penalizes breadth
4. Remove unused DLLs with 1-2 functions — AVG/Avast Evo-gen heuristic

**Unused import heuristic** (AVG/Avast Win64:Evo-gen): DLLs with only 1-2 functions that
are never called in the code trigger detection. Cap at 3 enriched DLLs max.

**Import hash (imphash)**: Each randomized build has a unique imphash — no hash-based blocking.

### 4. Byte-Level Features (Used by Symantec, AhnLab)

| Feature | Vanilla Go | Modified Build |
|---------|-----------|-----------------|
| File entropy | 6.85 | **7.44** |
| Byte histogram std | 0.0114 | 0.0068 (more uniform) |
| Null byte ratio | 17.6% | 10.6% |
| Printable ratio | 33.0% | 35.5% |

Higher file entropy (7.44 vs 6.85) comes from the WASM payload in debug sections. The byte
distribution is more uniform (lower std) — consistent with encrypted/compressed content.

### 5. String Features (Used by Most Engines)

| Feature | Vanilla Go | Modified Build |
|---------|-----------|-----------------|
| String count | 11,638 | 61,919 |
| Path strings | 1,759 | 14,468 |
| URL strings | 6 | 33 |
| MZ header strings | 2 | 5 |

High string count and path count come from Sliver's large codebase. Hard to change.

### 6. Data Directory Completeness

Both vanilla Go and the modified build are missing:
- `DEBUG` directory — legitimate software often has a PDB path here
- `LOAD_CONFIG` — security cookies, guard flags, etc.
- `TLS` — thread-local storage

These absences are shared with vanilla Go, so they don't add additional detection signal
_relative to baseline_. Do not add fake directories — they create inconsistencies.

### 7. Go-Specific Anomaly Composite

The analyzer's anomaly score tracks deviations from standard PE norms. The modified build in
the example below adds 3 anomalies beyond vanilla Go:
- `extreme_bss_ratio_208` — .data 34MB virtual / 163KB raw
- `phantom_edata` — .edata section exists but export directory is empty
- `debug_sections_over_40pct` — 50% of file is high-entropy compressed data

Vanilla Go already has: timestamp_zero, no_rich_header, linker_v3_go, numeric_section_names,
has_coff_symtab, no_debug_directory, no_load_config, dynamic_api_resolution, many_high_entropy_sections.

**Fixing the 3 extras is the highest-leverage structural target.**

## What Makes a Binary "Normal" to ML

ML classifiers are trained on millions of real Windows binaries. "Normal" means:
- Consistent toolchain signals (same linker version, section layout, import style throughout)
- Code+data sections dominate file size (not 50% compressed data)
- BSS/virtual size ratio typical for the toolchain
- Import DLLs actually used (no phantom imports)
- No phantom sections (section exists but directory entry is missing/empty)

**The goal is not to look like a generic Windows binary. The goal is to look like a
large, legitimate Go program.** Large Go programs exist and are clean on VT.
