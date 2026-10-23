# phish-triage roadmap

Each phase gets its own git branch (`phase-1-headers`, etc.). Merge to `main` only when the phase's "done when" list is fully checked and you can answer its "explain it back" questions without looking.

📸 = screenshot checkpoint. Save to `docs/screenshots/` with names like `p1-spoof-caught.png`. Scrub your email address and any personal info before committing.

**Loop for every task in Claude Code:**
1. paste the phase kickoff prompt (or the next task)
2. read Claude's plan → push back or approve
3. read every diff before accepting
4. run `pytest` yourself
5. log it in `docs/ai-dev-log.md` (prompt → what it did → what broke → how you fixed it)

---

## Phase 0 — setup
**Goal:** an empty but professional repo where tests run locally and on GitHub.

**Tasks**
- [ ] create a GitHub repo `phish-triage`, connect this folder to it
- [ ] `pyproject.toml`, `.venv`, install the stack from CLAUDE.md
- [ ] `.gitignore` (`.venv/`, `.env`, `samples/`, `__pycache__/`, `.cache/`)
- [ ] `.env.example` with empty keys
- [ ] pre-commit hooks: `ruff` + `gitleaks` (blocks you from committing secrets)
- [ ] one placeholder test + GitHub Actions workflow running ruff + pytest
- [ ] `docs/ai-dev-log.md` created

**Done when:** pushing to GitHub produces a green check.

**Kickoff prompt**
> Read CLAUDE.md and ROADMAP.md. We're doing Phase 0 only. Plan the setup: list every file you'll create and what it's for. Don't write code until I approve.

**Explain it back:** what does gitleaks do, and why does a security repo need it? What runs in the GitHub Actions workflow, and when?

---

## Phase 1 — parser + header analysis
**Goal:** `phish-triage analyze email.eml` prints sender and authentication findings.

**Tasks**
- [ ] `models.py`: `ParsedEmail`, `Finding`
- [ ] `parser.py`: load .eml with `policy.default`. Extract headers, plain body, HTML body, attachment parts. Must survive malformed files.
- [ ] sender checks: From vs Reply-To vs Return-Path domain mismatch, display name spoofing (`"PayPal" <random@gmail.com>`)
- [ ] auth checks: parse SPF / DKIM / DMARC results from `Authentication-Results`. **Only trust the topmost one**, the one your receiving server added. Attackers can insert fake ones lower down.
- [ ] received chain: list the hops, identify the originating external IP
- [ ] basic CLI output (plain text is fine for now)
- [ ] crafted fixtures: clean email, SPF fail, DMARC fail, reply-to mismatch, display-name spoof, malformed file

**Done when:** each fixture triggers exactly the findings it should, and the malformed file doesn't crash anything.

📸 **checkpoints**
- the tool catching a spoofed email (SPF/DMARC fail + reply-to mismatch)
- the same check passing on a real legit email from your inbox
- your first real bug: failing test → fix → passing (for the dev log)

**Kickoff prompt**
> Phase 1 from ROADMAP.md. Start with models.py and parser.py only. Plan first. Explain how Python's email library represents multipart messages before writing code.

**Explain it back:** SPF vs DKIM vs DMARC in one sentence each. Why trust only the top Authentication-Results header? Why does reading the Received chain bottom-up show you the email's path?

---

## Phase 2 — URL analysis
**Goal:** every link extracted, red flags raised, everything defanged.

**Tasks**
- [ ] extract URLs from the plain body and from HTML `href`s (beautifulsoup)
- [ ] mismatch check: visible link text shows one domain, the `href` goes to another
- [ ] raw IP URLs, URL shorteners (keep a list in config), punycode domains (`xn--`)
- [ ] lookalike check: edit distance against a brand list (paypal, microsoft, apple, your bank…)
- [ ] `defang()` helper used by all output
- [ ] fixtures for each flag + a clean newsletter with lots of legit links (false-positive check)

**Done when:** the newsletter fixture comes back with zero URL findings, and every flag fixture triggers its finding.

📸 **checkpoints**
- a mismatched link caught: show the visible text vs the real destination
- a lookalike domain flagged (`paypa1[.]com`)

**Kickoff prompt**
> Phase 2. Before coding, explain how phishers hide link destinations in HTML emails and how punycode lookalikes work. Then plan urls.py.

**Explain it back:** why defang? Why does a URL tool need a false-positive fixture? Why never fetch the URL to "check it"?

---

## Phase 3 — attachment analysis
**Goal:** every attachment fingerprinted and typed without ever being opened.

**Tasks**
- [ ] SHA256 + MD5 for each attachment (in memory)
- [ ] true type via magic bytes (`filetype`) vs the claimed extension. Flag mismatches.
- [ ] flag risky types: executables, macro-enabled office (`.docm`, `.xlsm`), `.iso`/`.img`, `.html`/`.htm`, `.lnk`, double extensions (`invoice.pdf.exe`)
- [ ] zip: list the filenames inside without extracting. Flag executables inside, flag password-protected archives.
- [ ] fixtures: harmless dummy files renamed to fake the risky cases (a text file named `.exe` is enough to test the logic)

**Done when:** all fixtures are flagged correctly, and nothing ever gets written to disk.

📸 **checkpoints**
- fake `.pdf` that's really an executable, caught
- zip-with-exe-inside flagged

**Kickoff prompt**
> Phase 3. Explain magic bytes and why extensions can't be trusted, then plan attachments.py. Remember the CLAUDE.md rule: never extract to disk.

**Explain it back:** why hash instead of open? Why are password-protected zips suspicious by themselves? Why do attackers love `.iso` and `.html` attachments?

---

## Phase 4 — threat intel enrichment
**Goal:** hashes, domains, URLs and the originating IP checked against real intel.

**Tasks**
- [ ] VirusTotal: hash, domain and URL **lookups only**, no uploads
- [ ] AbuseIPDB: originating IP (reuse logic from your IP reputation checker)
- [ ] URLhaus: URLs/domains (free, no key needed)
- [ ] cache (sqlite or json, 24h TTL) so repeat lookups don't burn rate limits
- [ ] rate-limit handling: back off on 429s, never crash on API errors. Record "enrichment unavailable" and continue.
- [ ] `--no-enrich` flag for offline runs
- [ ] all API calls mocked in tests

**Done when:** the tool runs fully with no keys / no network (`--no-enrich`), with keys it enriches, and tests pass offline.

📸 **checkpoints**
- an enrichment table: an indicator → VT detections / AbuseIPDB score
- the cache working (second run instant, no API calls)

**Kickoff prompt**
> Phase 4. Plan the enrich/ package: one module per source plus cache.py. Show how you'll mock the APIs in tests before writing the clients.

**Explain it back:** why is uploading a file to VT a data leak? What happens when an API is down? Why cache?

---

## Phase 5 — scoring + reports
**Goal:** findings become a verdict with reasons, shown three ways.

**Tasks**
- [ ] `config/scoring.yaml`: points per finding, verdict thresholds
- [ ] `scoring.py`: total the points, pick the verdict, keep the list of reasons
- [ ] `rich` terminal output: colored verdict banner, findings table, ✓/✗ for SPF/DKIM/DMARC, defanged IOC list
- [ ] JSON report (machine-readable, SIEM-ready)
- [ ] HTML report via jinja2: self-contained, clean, opens in any browser
- [ ] IOC section: everything an analyst would block

**Done when:** a malicious fixture → MALICIOUS, a clean fixture → CLEAN, each with a readable reason list, in all three formats.

📸 **checkpoints**
- terminal: malicious vs clean, side by side ← **main portfolio shot**
- HTML report, full page
- the JSON next to it (shows it's built for automation)

**Kickoff prompt**
> Phase 5. Plan scoring first and keep the weights in YAML so they can be tuned without code changes. Then the terminal output with rich. HTML last.

**Explain it back:** why must a verdict list its reasons? Why are the weights in config instead of code?

---

## Phase 6 — real-world validation
**Goal:** prove it works on real mail, not just your own fixtures.

**Tasks**
- [ ] put 20+ real phish into `samples/` (your spam folder + the `phishing_pot` repo) and 20+ legit emails (bank, amazon, newsletters). Work inside your UTM VM.
- [ ] run the tool across all of them, record the results in a table: TP / FP / TN / FN
- [ ] dig into every miss: why did it miss, or why did it false-alarm?
- [ ] tune `scoring.yaml`, re-run, record the before/after
- [ ] write `docs/validation.md`: method, results, misses, what you changed (no raw emails committed)

**Done when:** a results table exists with honest numbers, and every false positive/negative has an explanation.

📸 **checkpoints**
- the validation results table, before and after tuning
- one interesting real catch (redacted)
- one honest miss + your explanation (interviewers love this)

**Kickoff prompt**
> Phase 6. Write a batch script that runs the analyzer over samples/ and outputs a results CSV. It must never print raw email bodies. Then help me analyze the false positives.

**Explain it back:** what's a false positive vs a false negative, and which is worse for a SOC? (Trick: both. One causes alert fatigue, the other is a breach.)

---

## Phase 7 — polish + ship
**Goal:** a repo a hiring manager understands in 30 seconds.

**Tasks**
- [ ] README: one-line pitch, demo GIF at the top, the SOC workflow it fits into, mermaid architecture diagram, install/usage, safety design section, validation results, link to the AI dev log
- [ ] demo GIF (`vhs` or asciinema + agg): run on a phish → MALICIOUS → open the HTML report
- [ ] badges: CI passing, coverage %
- [ ] 1–2 sample HTML/JSON reports from crafted fixtures in `examples/`
- [ ] final pass on the AI dev log: add a short "what I learned" summary at the top
- [ ] pin the repo on your GitHub profile

📸 **checkpoints**
- the demo GIF
- green CI + coverage badge
- the finished README top section (for LinkedIn)

**Explain it back:** walk through the whole tool in 2 minutes, out loud. If you can't, find the part you're fuzzy on and go back to it.
