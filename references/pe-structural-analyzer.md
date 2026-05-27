# PE Structural Analyzer

Comprehensive 13-category PE feature extractor for ML detection research.
Covers everything EMBER uses plus Go-specific and Authenticode features.

## Installation

```bash
# Preferred: virtualenv
python3 -m venv .venv && . .venv/bin/activate && pip install pefile lief

# Alternative on PEP 668 systems without a venv
python3 -m pip install --break-system-packages pefile lief
```

## Script Location

```
./pe_structural_analyzer.py
```

(Bundled alongside `SKILL.md` in this skill directory.)

## Usage

```bash
# Analyze directory of samples with vanilla baseline and detection labels
python3 pe_structural_analyzer.py /tmp/samples/ \
  --baseline /tmp/vanilla_go.exe \
  --detections /tmp/detections.json

# Single file analysis
python3 pe_structural_analyzer.py /tmp/sample.exe

# Outputs
#   /tmp/pe_analysis.json  — full per-sample features (raw)
#   /tmp/pe_analysis.csv   — flattened for spreadsheet analysis
#   stdout                 — clean vs. detected comparison table
```

## Detection Labels File Format

```json
{
  "sample-01.exe": "clean",
  "sample-02.exe": "detected",
  "sample-03.exe": "detected"
}
```

## Output: Clean vs. Detected Comparison Table

The analyzer prints Cohen's d for every numeric feature:

```
Metric                      Clean mean     Det mean      Delta    Cohen d
---------------------------------------------------------------------------
BSS ratio                     208.3600     208.3600    +0.0000      0.000
Mean entropy                    5.7167       5.6953    -0.0214      0.973 ***
Total imports                  55.3333      53.9412    -1.3922      1.032 ***
```

Stars: `***` d>0.8, `**` d>0.5, `*` d>0.3

## Output: Vanilla Baseline Delta

When `--baseline` is provided, the analyzer prints every feature where the sample
differs from the vanilla binary:

```
--- SECTIONS ---
  bss_ratio: GO=6.42  MOD=208.36
  debug_like_pct: GO=0.2722  MOD=0.4979
  has_edata: GO=False  MOD=True

--- GO-SPECIFIC ---
  stack_reserve_is_go_default: GO=True  MOD=False

--- ANOMALY SCORE ---
  GO: 9 anomalies
  MOD: 12 anomalies = [..., extreme_bss_ratio_208, phantom_edata, debug_sections_over_40pct]
```

## Feature Categories Extracted

1. Header fields (linker version, timestamps, stack sizes, DLL characteristics)
2. Rich header (presence, entry count)
3. Section table (count, entropy stats, size ratios, flags, naming patterns)
4. Import table (DLL count, function count, suspicious API flags, imphash)
5. Data directories (which directories present, sizes)
6. String features (count, lengths, URL/path/registry patterns, printable ratio)
7. Byte statistics (file entropy, histogram distribution, null/FF ratios)
8. Go-specific features (BSS ratio, symtab, linker fingerprint, stack reserve)
9. Authenticode (signed, cert size, cert details)
10. Resource features (presence, section details)
11. Overlay (presence, size)
12. Version info (fields present, content)
13. Anomaly scores (composite count of structural deviations from toolchain norms)

## Building a Vanilla Baseline

```bash
mkdir -p /tmp/vanilla && cd /tmp/vanilla && go mod init hello
printf 'package main\nimport ("fmt";"os")\nfunc main(){fmt.Println("hello");os.Exit(0)}' > main.go
GOOS=windows GOARCH=amd64 go build -o /tmp/vanilla_go.exe .
```

Use a vanilla binary from the exact same Go version as your target binary.
