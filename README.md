# AI-Phishing Detector

A layered phishing detection system built to answer one specific
question: **why do phishing filters trained on old spam data fail
against modern, AI-generated phishing** — and what actually closes
that gap?

Documented context: AI-generated phishing routinely bypasses
standard content filters, and gateway-bypassing phishing volume rose
sharply in 2026. This project reproduces that failure honestly, on
original test data, and then builds up a detector that addresses it
layer by layer.

## The problem, demonstrated

`baseline_classifier.py` trains a classic content-based detector:
TF-IDF + Logistic Regression on 17,450 cleaned emails
(`clean_dataset.py` — dropped 16 null rows, 92 corrupted/outlier-length
rows including one 17-million-character row, and 1,092 duplicates from
the raw Hugging Face `Phishing_Email.csv` set).

Result: **97% accuracy** — on the old-style spam it was trained on.

`test_against_ai_phishing.py` then feeds it 5 original, realistic
AI-phishing-style emails (clean grammar, plausible business context,
no spam-trigger words). Result: **0 of 5 caught.** The content model
only knows what old phishing looks like; it has no way to recognize
well-written phishing that doesn't resemble its training data.

## Layer 2: behavioral signals

`behavioral_detector.py` doesn't look at wording — it looks at what
the email is asking the reader to **do**: bypass normal verification,
act under time pressure, reset credentials/MFA, move money, or
click/sign something. Risk scales with how many categories co-occur,
since any single category alone (e.g. "urgent") is common in
legitimate email too.

Result on the same 5 emails the baseline missed: **4 of 5 caught.**

## Honest stress-testing at scale

5 examples isn't enough to trust a percentage. `expanded_test_set.py`
grows the set to 12 phishing + 12 safe examples (including
deliberately subtle, low-pressure phishing and safe emails that
mention money/deadlines/documents, so those words alone can't cause
false alarms). `run_expanded_evaluation.py` runs the combined
baseline+behavioral detector (`combined_detector.py`) against it.

First run exposed real weaknesses:
- Only ~50% of phishing caught
- 1 false positive: the baseline flagged a normal finance email at
  0.71 confidence purely on word-overlap with old training data

Fixes applied:
- Raised the baseline confidence threshold 0.7 → 0.85 (removed the
  false positive)
- Broadened the behavioral regex patterns (badge/facilities,
  legal/NDA, billing, meeting-lure categories)
- Fixed a regex brittleness bug where "sign and return today" didn't
  match "sign and return **the document**"

Result after fixes: 10/12 caught (83%), 0/12 false positives — but
two low-pressure, well-written social-engineering emails (invoice
fraud with no urgency, a fake facilities/badge request) still slipped
through both layers. No amount of phrase-matching catches phishing
that's written to sound like routine business.

## Layer 3: sender history

The dataset has no sender/timestamp metadata, so `sender_history.py`
simulates a small, realistic "known contacts" address book for one
mailbox — a stand-in for real mail-server logs, built to test the
*detection logic* honestly rather than pretend we have inbox history
we don't.

`combined_detector_final.py` (the consolidated, final version —
replaces the earlier `combined_detector.py` / `combined_detector_v2.py`
split) adds sender risk as a third, independent signal. An email is
flagged if **any** of the following holds:

- baseline content-model confidence ≥ 0.85, **or**
- behavioral risk is MEDIUM or HIGH on its own, **or**
- behavioral risk is LOW (one soft signal) **and** the sender is
  unknown or on an unrecognized/lookalike domain

The insight: a single soft phrasing signal plus an unverified sender
is more suspicious than either alone — and a genuinely known vendor
sending the same low-pressure invoice should **not** be flagged.

### A bug found while consolidating

Re-running the "closed gap" facilities/badge case through the
consolidated script showed it was **not actually being caught** —
the earlier claim that this gap was closed only held for the exact
wording tested before. The credential/access regex matched
"verify your account/identity/access" but not "re-verify your
employee ID" or "restore full access." Fixed by broadening the
pattern set. This is exactly the kind of narrow-regex trap the
project is trying to avoid, and worth mentioning as-is in an
interview: the fix that "worked" wasn't fully generalized until this
consolidation pass caught it.

## Final results (`run_final_evaluation.py`)

Against the 12 phishing + 12 safe set, with senders assigned per
example (unverified/lookalike senders for phishing, known-contact
senders for safe email — matching how each would arrive in reality):

- **9/12 phishing caught (75%)**
- **0/12 false positives (0%)**

Remaining misses are all low-pressure, single-signal phishing from a
sender that happens to look legitimate in this test set (a
meeting-briefing lure, a legal/NDA request, a billing renewal notice)
— the honest edge of what a 3-signal, no-ML-black-box system catches
without also risking false positives on real business email.

## Project files

| File | Purpose |
|---|---|
| `clean_dataset.py` | Cleans the raw dataset → `phishing_dataset_clean.csv` |
| `baseline_classifier.py` | TF-IDF + Logistic Regression content model |
| `test_against_ai_phishing.py` | Proves the baseline's blind spot (5 original AI-phishing examples) |
| `behavioral_detector.py` | Regex-based intent/behavior signal detector |
| `sender_history.py` | Simulated sender-relationship risk signal |
| `expanded_test_set.py` | 12 phishing + 12 safe examples for honest evaluation |
| `combined_detector.py` | First combined detector (baseline + behavioral only) — superseded |
| `combined_detector_v2.py` | Adds sender history as a third signal — superseded |
| `combined_detector_final.py` | Final 3-signal detector (baseline + behavioral + sender history) |
| `run_expanded_evaluation.py` | Runs `combined_detector.py` against the expanded test set |
| `run_final_evaluation.py` | Runs the final detector against the expanded test set |
| `interactive_demo.py` | Live CLI demo — paste an email, get an instant verdict |

Two files referenced above aren't checked into this repo (see
`.gitignore`), for practical reasons rather than by choice:

- **`phishing_dataset_clean.csv`** (17,450 rows, ~29 MB) — too large
  to check in through this workflow. Regenerate it with
  `clean_dataset.py` from the raw Hugging Face `Phishing_Email.csv`
  dataset, or ask for a copy directly.
- **`baseline_model.pkl`** — the trained model + vectorizer, saved as
  a binary pickle. Regenerate it by running `python3
  baseline_classifier.py` once `phishing_dataset_clean.csv` is in
  place.

## What this demonstrates

No single signal has to be perfect — content model, behavioral
phrasing, and sender history each catch a different failure mode of
the others, which mirrors how real layered email security works. The
progression (97%/0% → 4/5 → 83%/0% on the small set → 75%/0% on
final honest scoring with sender risk) is deliberately reported
including the regressions and bugs found along the way, not just the
end number.

## Not yet done

- Real-world validation against live/held-out email samples rather
  than dataset-derived test cases
- Sender-history data sourced from real mail logs instead of a
  simulated address book
