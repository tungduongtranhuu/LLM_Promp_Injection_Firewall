# CLAUDE.md

Guidance for Claude Code working in this repository.

## Project in one paragraph
This repo started as an **LLM prompt-injection firewall** (rule-based detectors + risk scorer) and is being extended into **RAG Shield**: a lab that shows a RAG assistant being poisoned by an *indirect prompt injection*, the attack being **detected** (firewall + FIM → Wazuh SIEM), **investigated** (timeline, time of compromise, IOC hash), and the platform being **restored** from the last clean snapshot and **verified**. It is a portfolio project for cybersecurity / cyber-resilience internships (SOC + PRA angle). Target architecture: `docs/ARCHITECTURE.md`. Work plan and known bugs: `TODO.md`. Read both before starting a task.

## Commands
```bash
python -m venv venv && source venv/bin/activate
pip install -r requirements.txt
pytest -q                                  # must stay green
uvicorn app.main:app --reload              # API on :8000
docker compose up -d                       # ollama + app
python -m resilience.drill                 # full scenario (once implemented)
```

## Architecture rules
- **Detectors only detect, the scorer only scores, rules hold the numbers.** Detectors return plain dicts of findings and never compute scores. All weights and thresholds live in `app/scoring/rules.py`, the **single source of truth**. `config.py` may override them from env vars but must not redefine them.
- Every scan goes through `app/pipeline.py::scan(text, context)`, where `context ∈ {"user_prompt","document","retrieved_chunk","llm_output"}`. Context-specific behaviour (e.g. Markdown is normal in `document`) is configured in `rules.py`, never with `if` branches scattered across detectors.
- Text variants (normalized, de-obfuscated, decoded) are produced only in `app/normalize.py`.
- Every security-relevant action writes **one JSON line** to `logs/firewall.jsonl` through `app/logging/audit.py`, following the schema in `docs/ARCHITECTURE.md §3.3`: UTC ISO-8601 `ts` with milliseconds, `source`, `event_type`, `request_id`, `decision`, `score`. Never log full secrets or full prompts: use `excerpt` (≤200 chars) plus a sha256. This file is the contract with Wazuh, so do not rename fields without updating `siem/wazuh/local_rules.xml`.
- Resilience scripts in `resilience/` are runnable as `python -m resilience.<name>`, are **idempotent**, print a short human summary, and also emit `resilience.*` audit events.
- Restore never deletes compromised data: it moves it into `quarantine/<ts>/` (forensic evidence).
- Snapshot selection must satisfy all three: created before `t_compromise`, manifest checksums valid, and does **not** contain the IOC hash. Keep a test for the trap case where the newest snapshot is poisoned.

## Code conventions
- Python 3.11+, type hints everywhere, `pydantic` models for API and scan results, `pathlib` for paths, `datetime.now(timezone.utc)` (never naive datetimes).
- Small pure functions. Detectors must have no I/O and no network access.
- Regex: precompile at class level, use `re.IGNORECASE` instead of lowercasing in some places and not others, and use `\b` word boundaries to limit false positives.
- No new dependency without adding it to `requirements.txt` with a pinned version.
- Code identifiers and comments in English. User-facing docs (README, runbook) in French.

## Testing
- Each new detector pattern needs **both** a true-positive and a false-positive test (a benign sentence that must NOT match).
- Track detection quality on `eval/benign_prompts.txt` and `eval/attack_prompts.txt`. When changing detectors, run the eval and report FP/FN rates before and after.
- Tests must not require Ollama, Docker or Wazuh. Mock the LLM provider and use `tmp_path` for the corpus, chroma and backups.

## Safety and scope
- `resilience/attack.py` is a **lab simulation**: it only writes to this repo's `data/corpus/` and uses the reserved domain `acme-support-reset.example`. Never target real domains or real systems.
- Never commit `.env`, `data/chroma/`, `backups/`, `quarantine/`, `logs/` or `reports/`.

## How to work
- Work phase by phase (P1 → P4 in `TODO.md`). Before coding, state which TODO items you are addressing and the files you will touch.
- Prefer small commits with conventional messages (`feat:`, `fix:`, `test:`, `docs:`, `refactor:`).
- After each change: run `pytest -q`, fix failures, then tick the item in `TODO.md`.
- If a design choice is not covered here or in ARCHITECTURE.md, ask instead of guessing.
- Do not implement features listed only as "Roadmap/Bonus" unless asked.
