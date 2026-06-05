# Experiment Categories & Tracking Template

## Change Category Taxonomy

Before running any experiment, classify the proposed change. Category determines risk.

### Category A — Move Toward Toolchain Baseline (PREFERRED)

Changes that make the binary more consistent with a vanilla binary from the same toolchain.
These reduce anomaly count without creating toolchain inconsistencies.

| Change | Target Feature | Expected Direction | On-sensor model feature |
|--------|---------------|-------------------|---------------------|
| Remove phantom .edata section | phantom_edata anomaly | -1 anomaly | BM07 (Export dir) |
| Revert stack reserve to Go default (0x200000) | stack_reserve inconsistency | -1 anomaly | BM03-04 |
| Prune enriched DLLs to ≤3 | unused_import heuristic | -1 engine (AVG/Avast) | **ReUM (rank #15)** |
| Remove risky DLL names (netapi32, ole32, winhttp) | AVG/Avast Evo-gen | Engine-specific | ReUM + specific Re codes |
| Prune risky product names from VERSIONINFO pool | product name corpus | Engine-specific | Te pass |
| Prune risky file versions | version ML feature | Engine-specific | Te pass |
| Remove CreateMutex imports if sync not needed | Re40 on-sensor indicator | **Model rank #7** | **Re40 (25 tree refs)** |
| Minimize total import DLL count | Import diversity score | **Model rank #15** | **ReUM (22 tree refs)** |
| Ensure .text entropy stays < 7.0 | Entropy threshold | Avoids FPE0 trigger | **FPE0 (feature 950)** |

**Expected behavior**: Lowers anomaly score, moves toward vanilla baseline delta.
**Risk**: Low — making things look more like vanilla Go is safe.

### Category B — Structural Ratio Changes (MEASURE CAREFULLY)

Changes that affect key ratios ML models weight heavily. These require careful measurement
because some ratio changes that look better on paper trigger different classifiers.

| Change | Target Feature | Risk |
|--------|---------------|------|
| Compress/strip debug sections | debug_like_pct | Medium — may expose other signals |
| Split .data section to reduce BSS ratio | bss_ratio (208x → lower) | High — complex PE surgery |
| Embed WASM in .text instead of debug sections | entropy distribution | Very High |
| Reduce total file size | file entropy, size | Medium |

**Required measurement**: Run analyzer before and after to verify the ratio actually changed.
Upload to VT only after confirming the feature shifted.

**The .text inflation anti-pattern**: Do NOT pad .text to improve code% ratio.
ML detects .text SIZE anomaly (5.3MB vs typical 3.6MB), not just entropy.
XOR padding also raises entropy from 6.12 to 6.99 — triggers Bkav/Trapmine.

### Category C — Fight Toolchain Identity (DANGEROUS — AVOID)

Changes that make the binary inconsistent with its actual toolchain. These create
contradictory signals that ML classifiers interpret as evasion attempts.

| Change | Why It Fails |
|--------|-------------|
| Patch linker version 3.0 → 14.38 | Section layout, import style, strings still scream Go |
| Add fake Rich header | Inconsistent with Go section naming and structure |
| Change timestamp from 0 to a date | Go binaries naturally have timestamp=0; changing it is anomalous |
| Strip .symtab | Go always has it; absence is inconsistent with the toolchain |
| Strip numeric section names (/4, /19…) | These ARE the debug section names; removing breaks the binary |
| Add fake DEBUG directory | Inconsistent with Go's lack of PDB path |
| Add fake LOAD_CONFIG | Go binaries don't generate this; fake content is detectable |

**The consistency principle**: ML classifiers see a feature vector spanning dozens of
dimensions. If 40 features say "this is Go" and 3 features say "this is MSVC", the
inconsistency score rises — not falls. Every Category C change ADDS to the detection score.

## Experiment Tracking Template

Copy this table for each experiment batch. Update after receiving VT results.

```
Batch: [name]  Date: [date]  Base Clean Rate: [X%]  Samples: [N]

| Exp | Change                  | N  | Clean | Rate | Delta | Anomaly | Vanilla Δ | Keep? |
|-----|------------------------|----|-------|------|-------|---------|-----------|-------|
| B   | — baseline             | 20 |  3/20 | 15%  | —     | 12      | 12        | —     |
| 1   | [change description]   | 20 |  ?/20 | ?%   | ?%    | ?       | ?         | ?     |
| 2   | [change description]   | 20 |  ?/20 | ?%   | ?%    | ?       | ?         | ?     |
```

**Minimum required columns**: Change, N, Clean, Rate, Delta. Anomaly score and Vanilla Δ
come from the PE structural analyzer and are mandatory for structural experiments.

## A-Tier Validation Results (2026-04-08, n=10 per experiment)

Post-processing patches applied to existing builds. Baseline: 15% clean, 80% AhnLab, 60% Symantec.

| Experiment | Category | Clean% | AhnLab | Symantec | New Engines | Verdict |
|-----------|----------|--------|--------|----------|-------------|---------|
| **Baseline** (original 20) | — | 15% | 80% | 60% | — | — |
| **remove-edata** | A (toward Go) | **0%** | 90% | **0%** | **+Bkav 90%** | WORSE — traded Symantec for Bkav |
| **revert-stack** (→0x200000) | A (toward Go) | **0%** | 90% | **80%** | +Microsoft | WORSE — Symantec up, 0% clean |
| **patch-linker** (→14.38) | C (fight identity) | 20% | 70% | 50% | — | Neutral (within noise) |
| **set-timestamp** (→recent) | C (fight identity) | **0%** | 70% | 30% | **+AVG/Avast 50%, +Bkav 40%** | MUCH WORSE |

**Key findings:**
- Every A-tier change made things **equal or worse** — confirms header tweaks don't help
- Zeroing sections creates PE anomalies that trigger new engines (Bkav)
- Adding timestamps to a Go binary (which naturally has timestamp=0) is catastrophic
- Patching linker version was surprisingly neutral — AhnLab/Symantec weight structure over header
- **Root cause is structural ratios** (BSS 208x, 50% high-entropy data, file entropy 7.44), not headers

## Proven Effective Changes (Historical)

| Change | Clean Rate Before | Clean Rate After | Engine Eliminated |
|--------|-----------------|-----------------|------------------|
| Cap enriched DLLs at 3 (was 3-5) | 56% | 96% | AVG/Avast (Win64:Evo-gen) |
| Prune netapi32/ole32/winhttp | 25% | ~15% (signing needed) | AVG/Avast |
| HashiCorp self-signing | 15% | 67% | CrowdStrike |
| Product name pruning | 67% | 87% | Cynet, remaining AVG |
| YARA kill (wazero type renaming) | n/a | n/a | YARA-based engines |

## VT API Helpers

```bash
# Upload with rate limiting (16s gap for free tier)
VT_KEY=$(cat /path/to/vt_apikey)
upload_sample() {
  local file="$1"
  UPLOAD_URL=$(curl -s 'https://www.virustotal.com/api/v3/files/upload_url' \
    -H "x-apikey: $VT_KEY" | python3 -c "import sys,json; print(json.load(sys.stdin)['data'])")
  curl -s --request POST --url "$UPLOAD_URL" \
    --header "x-apikey: $VT_KEY" --form "file=@$file" > /dev/null
  sleep 16
}

# Pull results by SHA256
sha256() { command -v sha256sum >/dev/null && sha256sum "$1" | cut -d' ' -f1 || shasum -a 256 "$1" | cut -d' ' -f1; }
get_result() {
  local file="$1"
  local sha=$(sha256 "$file")
  curl -s "https://www.virustotal.com/api/v3/files/$sha" -H "x-apikey: $VT_KEY" | \
    python3 -c "
import sys,json
d=json.load(sys.stdin)
r=d.get('data',{}).get('attributes',{}).get('last_analysis_results',{})
dets={k:v for k,v in r.items() if v.get('category')=='malicious'}
print(f'{len(dets)} dets: {sorted(dets.keys())}')
"
  sleep 4
}
```
