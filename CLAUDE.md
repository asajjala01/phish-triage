# phish-triage — project rules for Claude Code

## what this is
A CLI tool that takes a suspicious `.eml` file, analyzes headers, links and attachments, enriches indicators with threat intel, and outputs a verdict (CLEAN / SUSPICIOUS / MALICIOUS) with the reasons behind it. It automates the triage half of an L1 SOC phishing ticket. A human analyst still makes the final call.

Portfolio project. The owner (Abe) is building it to learn, and must be able to explain every line in an interview. Optimize for clarity over cleverness.

## hard safety rules — never break these
1. **Never fetch, resolve, or visit any URL found in an email.** Links are treated as text only. No HTTP requests to email-derived URLs, no DNS lookups on them.
2. **Never execute, open, render, or extract-to-disk any attachment.** Read bytes in memory to hash and identify type. Archive contents may be *listed*, never extracted.
3. **Threat intel lookups are by hash / domain / IP / URL string only.** Never upload files to VirusTotal or any other service.
4. **Never commit real emails, real attachments, or API keys.** Test fixtures in `tests/fixtures/` must be crafted samples. Real samples live in `samples/` which is gitignored.
5. **All output that contains URLs or domains must be defanged** (`hxxp://evil[.]com`) unless a flag explicitly disables it.

If a requested change would break one of these, stop and say so instead of doing it.

## stack
- Python 3.11+, virtualenv in `.venv/`
- stdlib `email` (use `policy.default`) for parsing
- `typer` CLI, `rich` terminal output, `jinja2` HTML report
- `beautifulsoup4` for HTML bodies
- `filetype` for magic-byte detection (pure Python. Do NOT use python-magic, it needs libmagic)
- `requests` for threat intel APIs, `pyyaml` for scoring config
- `pytest`, `pytest-cov`, `ruff`

## layout
```
src/phish_triage/
  cli.py           # entry point
  models.py        # dataclasses: ParsedEmail, Finding, Indicator, Verdict
  parser.py        # .eml -> ParsedEmail
  headers.py       # sender + auth + received-chain checks
  urls.py          # extraction, red flags, defanging
  attachments.py   # hashing, true type, risky types
  enrich/          # one module per intel source + cache.py
  scoring.py       # findings -> score -> verdict
  report/          # terminal.py, json_report.py, html_report.py + templates/
tests/
  fixtures/        # crafted .eml files, one red flag each where possible
config/scoring.yaml
docs/ai-dev-log.md
samples/           # gitignored, real emails
```

## code standards
- Type hints everywhere. Dataclasses for structured data, not loose dicts.
- Every check returns `Finding` objects (id, severity, description, evidence) rather than printing.
- Specific exceptions, never bare `except:`. Malformed emails must not crash the tool. Record a finding and continue.
- Every new check ships with tests: one fixture that triggers it, one that doesn't.
- External APIs are always mocked in tests. Tests must pass with no network and no API keys.
- Secrets come from `.env` only (`VT_API_KEY`, `ABUSEIPDB_API_KEY`). `.env.example` is committed, `.env` is not.
- Run `ruff check` and `pytest` before saying a task is done.

## how to work with Abe
- Work **one phase at a time** from `ROADMAP.md`. Don't build ahead into later phases.
- Plan before coding: list the files you'll touch and why, then wait for a go-ahead.
- Keep diffs small. One task per change.
- After each task, give a 3–5 bullet summary: what changed, why, and anything non-obvious (a security concept, a parsing gotcha). Abe uses these for `docs/ai-dev-log.md`.
- If you're unsure about an email standard or an API's behavior, say so. Don't guess.
- Point out when a screenshot checkpoint from `ROADMAP.md` has been reached.
