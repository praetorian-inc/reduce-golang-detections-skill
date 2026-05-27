# reduce-golang-detections-skill

A [Claude Code](https://claude.com/claude-code) skill for systematically reducing VirusTotal and EDR detection rates on compiled Go binaries through structural analysis, iterative A/B testing, and ML feature vector optimization.

> A companion blog post will be linked here once published.

## What this is

Modern EDR detections on Go binaries are dominated by statistical ML classifiers (e.g. Microsoft `Wacatac.B!ml`, `ML.Attribute.HighConfidence`, `MalwareX-gen`, `Evo-gen`) rather than fixed-byte YARA rules. Defeating an ML classifier is a fundamentally different problem from defeating a signature — renaming strings and swapping imports often makes detection *worse*, because the resulting binary diverges further from the vanilla toolchain baseline the classifier has learned as "normal."

This skill packages a disciplined methodology for that problem:

- **Triage detection type before remediation.** Label every hit as YARA-style or ML-style. The fixes are different and not interchangeable.
- **Change one variable per experiment.** 10–20 samples per arm, control and variant built in the same VT upload window — Wacatac retrains on roughly a daily cadence, so a control batch from yesterday is not a valid A/B test.
- **Measure with a comprehensive PE structural analyzer** (included) before and after each change, and compare deltas against a vanilla binary from the same toolchain.
- **Camouflage, not concealment.** Give the classifier a believable answer to "what is this binary?" — mimicking the gopclntab symbol fingerprint of a single coherent large Go project consistently outperforms stripping, padding, or obfuscation.
- **Recognize the irreducible floor.** Once detection drops to ~15–25% on VirusTotal (the stochastic floor near the ML threshold), further structural optimization rarely pays back, and VT is not ground truth for real endpoints.

## What's in the box

| File | Purpose |
| --- | --- |
| `SKILL.md` | The skill itself — methodology, prerequisites, phased workflow, and the core principles above. Load this into Claude Code. |
| `pe_structural_analyzer.py` | Standalone Python analyzer that extracts the full PE structural feature vector (sections, imports, exports, resources, gopclntab, entropy, etc.) and produces a baseline/delta JSON report. |
| `references/pe-structural-analyzer.md` | How to run the analyzer and interpret its output. |
| `references/pe-structural-features.md` | Catalog of structural features observed across vanilla vs. modified Go builds, with which features actually correlate with detection. |
| `references/experiment-categories.md` | Catalog of experiment categories that have and have not worked in practice, including dead ends to avoid. |

## Requirements

- Python 3 with `pefile` and `lief` (a venv is recommended; on PEP 668 systems use `--break-system-packages` if you must install system-wide).
- A VirusTotal API key.
- A vanilla binary from the same toolchain as your target (e.g. `GOOS=windows GOARCH=amd64 go build`) for delta comparison.

## Using the skill with Claude Code

Drop `SKILL.md`, `pe_structural_analyzer.py`, and the `references/` directory into a location Claude Code can read as a skill, then invoke the workflow when you have a high-detection binary you need to bring down. The skill will walk through baseline collection, structural analysis, hypothesis selection, and per-experiment A/B testing.

## Scope and intent

This is a defensive-research and authorized-engagement tool published by Praetorian to share methodology for understanding how modern ML-based EDR classifiers respond to changes in compiled binaries. It is intended for use on binaries you are authorized to test, in the context of red-team engagements, detection-engineering research, and toolchain hardening.

## License

Apache License 2.0 — see [LICENSE](LICENSE).
