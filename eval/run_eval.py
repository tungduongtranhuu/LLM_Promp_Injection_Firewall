"""Measure the firewall's false-positive and false-negative rates on the eval sets.

Usage:
    python -m eval.run_eval                         # dev set, both contexts
    python -m eval.run_eval --context retrieved_chunk --show-errors
    python -m eval.run_eval --holdout               # aggregate numbers only

Dataset layout (dev set in eval/, holdout in eval/holdout/, same layout):
    benign_prompts.txt, attack_prompts.txt   one prompt per line   -> context user_prompt
    chunks/benign/*.md, chunks/attack/*.md   one file per sample   -> context retrieved_chunk / document

Two detection levels are reported for each set:
    warn  : a benign sample is a false positive if its decision is not ALLOW;
            an attack sample is a false negative if its decision is ALLOW.
    block : a benign sample is a false positive if its decision is BLOCK;
            an attack sample is a false negative if its decision is not BLOCK.

The script calls the scan function directly, so it never writes to the audit log.
It always exits 0 when it runs: it is a report, not a gate.
"""

from __future__ import annotations

import argparse
import sys
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Literal

EVAL_DIR = Path(__file__).resolve().parent
HOLDOUT_DIR = EVAL_DIR / "holdout"

Label = Literal["benign", "attack"]
Level = Literal["warn", "block"]
ScanFn = Callable[[str, str], Any]  # (text, context) -> object with .decision, .score and optionally .findings

PROMPT_CONTEXTS = ("user_prompt",)
CHUNK_CONTEXTS = ("retrieved_chunk", "document")
DEFAULT_CONTEXTS = ("user_prompt", "retrieved_chunk")
PROMPT_FILES: dict[Label, str] = {"benign": "benign_prompts.txt", "attack": "attack_prompts.txt"}
CHUNK_DIRS: dict[Label, str] = {"benign": "chunks/benign", "attack": "chunks/attack"}


@dataclass(frozen=True)
class Sample:
    sample_id: str
    text: str


@dataclass(frozen=True)
class Outcome:
    sample: Sample
    decision: str
    score: float
    techniques: tuple[str, ...]


@dataclass(frozen=True)
class SetReport:
    label: Label
    context: str
    outcomes: tuple[Outcome, ...]

    @property
    def total(self) -> int:
        return len(self.outcomes)

    def count(self, decision: str) -> int:
        return sum(1 for o in self.outcomes if o.decision == decision)

    def errors(self, level: Level) -> list[Outcome]:
        """Misclassified samples at the given level (FP for benign, FN for attack)."""
        if self.label == "benign":
            wrong = (lambda d: d != "ALLOW") if level == "warn" else (lambda d: d == "BLOCK")
        else:
            wrong = (lambda d: d == "ALLOW") if level == "warn" else (lambda d: d != "BLOCK")
        return [o for o in self.outcomes if wrong(o.decision)]

    def rate(self, level: Level) -> float:
        return len(self.errors(level)) / self.total if self.total else 0.0


def load_prompts(path: Path) -> list[Sample]:
    """One sample per non-blank line; lines starting with '#' are comments."""
    samples = []
    for lineno, line in enumerate(path.read_text(encoding="utf-8").splitlines(), start=1):
        if line.strip() and not line.lstrip().startswith("#"):
            samples.append(Sample(f"{path.name}:{lineno}", line))
    return samples


def load_chunks(directory: Path) -> list[Sample]:
    """One sample per .md file, scanned whole (no chunking before P2)."""
    return [Sample(p.name, p.read_text(encoding="utf-8")) for p in sorted(directory.glob("*.md"))]


def load_set(root: Path, context: str, label: Label) -> list[Sample] | None:
    """Samples for one context and label, or None if that part of the dataset is absent."""
    if context in PROMPT_CONTEXTS:
        path = root / PROMPT_FILES[label]
        return load_prompts(path) if path.is_file() else None
    if context in CHUNK_CONTEXTS:
        path = root / CHUNK_DIRS[label]
        return load_chunks(path) if path.is_dir() else None
    raise ValueError(f"unknown context: {context!r}")


def _techniques(result: Any) -> tuple[str, ...]:
    names = set()
    for finding in getattr(result, "findings", None) or ():
        if isinstance(finding, str):
            names.add(finding)
        elif isinstance(finding, dict):
            names.add(str(finding.get("technique", finding)))
        else:
            names.add(str(getattr(finding, "technique", finding)))
    return tuple(sorted(names))


def evaluate(samples: Sequence[Sample], label: Label, context: str, scan_fn: ScanFn) -> SetReport:
    outcomes = []
    for sample in samples:
        result = scan_fn(sample.text, context)
        outcomes.append(Outcome(sample, str(result.decision), float(result.score), _techniques(result)))
    return SetReport(label, context, tuple(outcomes))


def format_report(report: SetReport) -> str:
    if report.label == "benign":
        first, second = "FP (WARN+BLOCK)", "FP (BLOCK)    "
    else:
        first, second = "FN (ALLOW)     ", "FN (not BLOCK)"
    warn, block = report.errors("warn"), report.errors("block")
    return (
        f"{report.label:<7}{report.total:>4} | "
        f"ALLOW {report.count('ALLOW'):>3}  WARN {report.count('WARN'):>3}  BLOCK {report.count('BLOCK'):>3} | "
        f"{first} {len(warn):>3} {report.rate('warn'):6.1%} | "
        f"{second} {len(block):>3} {report.rate('block'):6.1%}"
    )


def format_errors(report: SetReport, level: Level = "warn", width: int = 80) -> list[str]:
    kind = "FP" if report.label == "benign" else "FN"
    lines = []
    for o in report.errors(level):
        text = " ".join(o.sample.text.split())
        text = text if len(text) <= width else text[: width - 1] + "…"
        techniques = ",".join(o.techniques) or "-"
        lines.append(f"  {kind} {o.decision:<5} {o.score:5.1f}  {o.sample.sample_id:<38} [{techniques}]  {text}")
    return lines


def run(root: Path, contexts: Sequence[str], scan_fn: ScanFn, show_errors: bool, title: str) -> list[SetReport]:
    reports = []
    for context in contexts:
        print(f"== {title} | context: {context} ==")
        for label in ("benign", "attack"):
            samples = load_set(root, context, label)
            if samples is None:
                print(f"{label:<7}   - | skipped: not present in {root}")
                continue
            report = evaluate(samples, label, context, scan_fn)
            reports.append(report)
            print(format_report(report))
            if show_errors:
                print("\n".join(format_errors(report)) or "  (none)")
        print()
    return reports


def _default_scan_fn() -> ScanFn:
    from app.pipeline import scan

    return scan


def main(argv: Sequence[str] | None = None, scan_fn: ScanFn | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--context", choices=PROMPT_CONTEXTS + CHUNK_CONTEXTS,
                        help="evaluate a single context (default: user_prompt and retrieved_chunk)")
    parser.add_argument("--show-errors", action="store_true", help="list misclassified samples (dev set only)")
    parser.add_argument("--holdout", action="store_true",
                        help="evaluate eval/holdout/ instead of the dev set; aggregate numbers only")
    parser.add_argument("--root", type=Path, help=argparse.SUPPRESS)  # test hook: alternative dataset root
    args = parser.parse_args(argv)

    if args.holdout and args.show_errors:
        parser.error("--show-errors is not allowed with --holdout: holdout samples are never printed")

    root = args.root or (HOLDOUT_DIR if args.holdout else EVAL_DIR)
    contexts = (args.context,) if args.context else DEFAULT_CONTEXTS
    title = "HOLDOUT" if args.holdout else "dev set"
    run(root, contexts, scan_fn or _default_scan_fn(), args.show_errors, title)
    return 0


if __name__ == "__main__":
    sys.exit(main())
