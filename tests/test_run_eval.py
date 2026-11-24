"""Tests for eval/run_eval.py: dataset loading, FP/FN arithmetic, holdout safeguards."""

from pathlib import Path
from types import SimpleNamespace

import pytest

from eval.run_eval import Sample, evaluate, load_chunks, load_prompts, load_set, main


def stub_scan(text: str, context: str) -> SimpleNamespace:
    """Decision is encoded in the sample text, so tests control it exactly."""
    for decision in ("BLOCK", "WARN"):
        if decision in text:
            return SimpleNamespace(decision=decision, score=50.0, findings=[{"technique": "stub"}])
    return SimpleNamespace(decision="ALLOW", score=0.0, findings=[])


def make_dataset(root: Path) -> None:
    (root / "benign_prompts.txt").write_text("# comment\n\nhello\nWARN here\nBLOCK here\nbye\n", encoding="utf-8")
    (root / "attack_prompts.txt").write_text("ALLOW? no: plain\nWARN x\nBLOCK y\nBLOCK z\n", encoding="utf-8")
    for label, files in (("benign", {"a.md": "# doc\nplain"}), ("attack", {"b.md": "BLOCK", "c.md": "plain"})):
        d = root / "chunks" / label
        d.mkdir(parents=True)
        for name, body in files.items():
            (d / name).write_text(body, encoding="utf-8")


def test_load_prompts_skips_blank_and_comment_lines(tmp_path: Path) -> None:
    make_dataset(tmp_path)
    samples = load_prompts(tmp_path / "benign_prompts.txt")
    assert [s.text for s in samples] == ["hello", "WARN here", "BLOCK here", "bye"]
    assert samples[0].sample_id == "benign_prompts.txt:3"


def test_load_chunks_reads_one_sample_per_file_sorted(tmp_path: Path) -> None:
    make_dataset(tmp_path)
    samples = load_chunks(tmp_path / "chunks" / "attack")
    assert [s.sample_id for s in samples] == ["b.md", "c.md"]


def test_benign_fp_rates_at_both_levels() -> None:
    samples = [Sample(str(i), t) for i, t in enumerate(["ok", "WARN", "BLOCK", "ok"])]
    report = evaluate(samples, "benign", "user_prompt", stub_scan)
    assert len(report.errors("warn")) == 2  # WARN + BLOCK are false positives
    assert len(report.errors("block")) == 1  # only BLOCK
    assert report.rate("warn") == 0.5
    assert report.rate("block") == 0.25


def test_attack_fn_rates_at_both_levels() -> None:
    samples = [Sample(str(i), t) for i, t in enumerate(["plain", "WARN", "BLOCK", "BLOCK"])]
    report = evaluate(samples, "attack", "user_prompt", stub_scan)
    assert len(report.errors("warn")) == 1  # only ALLOW is missed
    assert len(report.errors("block")) == 2  # ALLOW + WARN are not blocked
    assert report.count("BLOCK") == 2


def test_load_set_maps_contexts_to_sources(tmp_path: Path) -> None:
    make_dataset(tmp_path)
    assert len(load_set(tmp_path, "user_prompt", "attack")) == 4
    assert len(load_set(tmp_path, "retrieved_chunk", "attack")) == 2
    assert load_set(tmp_path / "missing", "user_prompt", "benign") is None
    with pytest.raises(ValueError):
        load_set(tmp_path, "llm_output", "benign")


def test_holdout_refuses_show_errors(tmp_path: Path) -> None:
    with pytest.raises(SystemExit):
        main(["--holdout", "--show-errors", "--root", str(tmp_path)], scan_fn=stub_scan)


def test_holdout_prints_aggregates_only(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    make_dataset(tmp_path)
    assert main(["--holdout", "--root", str(tmp_path)], scan_fn=stub_scan) == 0
    out = capsys.readouterr().out
    assert "HOLDOUT" in out and "FP (WARN+BLOCK)" in out
    assert "here" not in out and "plain" not in out  # no sample text leaks


def test_missing_parts_are_skipped(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    (tmp_path / "attack_prompts.txt").write_text("BLOCK\n", encoding="utf-8")
    main(["--holdout", "--context", "user_prompt", "--root", str(tmp_path)], scan_fn=stub_scan)
    out = capsys.readouterr().out
    benign_line, attack_line = out.splitlines()[1:3]
    assert benign_line.startswith("benign") and "skipped" in benign_line
    assert attack_line.split()[:2] == ["attack", "1"]
