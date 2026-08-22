"""
combined_detector.py
----------------------
Merges the two detectors built so far into ONE final verdict:

1. Baseline content model (baseline_classifier.py) - catches old-style,
   pattern-heavy spam/phishing.
2. Behavioral signal detector (behavioral_detector.py) - catches
   intent-based red flags (urgency, verification bypass, credential/
   financial requests) regardless of how well-written the email is.

Final verdict logic:
- FLAG AS PHISHING if the baseline is highly confident (>0.7) OR the
  behavioral risk is MEDIUM or HIGH.
- Otherwise, treat as safe.

This mirrors how real layered email security works: no single model
has to be perfect, because the two approaches catch different failure
modes of each other.

Also includes a small set of GENUINELY SAFE example emails - a busy
executive's real note, an internal password reset warning that's
actually legitimate, etc. - to check the combined system doesn't
just cry wolf on everyday email. Catching phishing perfectly while
flagging every real email as suspicious would be a worse system, not
a better one (this is the alert-fatigue problem).
"""

from baseline_classifier import load_model, predict as baseline_predict
from behavioral_detector import analyze as behavioral_analyze
from test_against_ai_phishing import AI_STYLE_PHISHING_EXAMPLES

BASELINE_CONFIDENCE_THRESHOLD = 0.7

# Genuinely safe, everyday business emails - written to sound completely
# normal, including a couple that mention deadlines or account topics
# (since those words alone shouldn't be enough to trigger a false alarm).
SAFE_EXAMPLES = [
    (
        "Hi team, just a reminder that our sprint planning meeting moved "
        "to 2pm tomorrow instead of 10am. Same room. Let me know if that "
        "doesn't work for anyone.",
        "routine schedule change"
    ),
    (
        "Hey, I finally got around to resetting my own password after IT "
        "sent that reminder last week - all good now, just wanted to "
        "confirm I can still access the shared drive.",
        "legitimate first-person password reset mention"
    ),
    (
        "Hi Maria, attached is the invoice for October's contractor hours "
        "as discussed on our call. No change to our usual payment details. "
        "Let me know if anything looks off.",
        "routine invoice, explicitly confirms no change to payment details"
    ),
    (
        "Quick heads up - the client asked if we could turn around the "
        "draft by end of day Friday instead of next week. Should be doable "
        "but let me know if that's a problem for your part.",
        "normal deadline pressure, no request for money/credentials"
    ),
]


def combined_verdict(text, model, vectorizer):
    _, baseline_prob = baseline_predict(text, model, vectorizer)
    behavioral_result = behavioral_analyze(text)

    baseline_flag = baseline_prob >= BASELINE_CONFIDENCE_THRESHOLD
    behavioral_flag = behavioral_result["risk"] in ("MEDIUM", "HIGH")

    final_flag = baseline_flag or behavioral_flag

    reasons = []
    if baseline_flag:
        reasons.append(f"baseline content model confidence {baseline_prob:.2f}")
    if behavioral_flag:
        fired = [k for k, v in behavioral_result["signals"].items() if v]
        reasons.append(f"behavioral risk {behavioral_result['risk']} ({', '.join(fired)})")

    return {
        "flagged": final_flag,
        "baseline_prob": baseline_prob,
        "behavioral_risk": behavioral_result["risk"],
        "reasons": reasons,
    }


def run_report():
    model, vectorizer = load_model()

    print("=== COMBINED DETECTOR: AI-phishing-style test emails ===\n")
    caught = 0
    for text, description in AI_STYLE_PHISHING_EXAMPLES:
        result = combined_verdict(text, model, vectorizer)
        verdict = "FLAGGED" if result["flagged"] else "missed"
        if result["flagged"]:
            caught += 1
        print(f"[{verdict}] {description}")
        if result["reasons"]:
            print(f"    why: {'; '.join(result['reasons'])}")
        print()
    print(f"Phishing caught: {caught}/{len(AI_STYLE_PHISHING_EXAMPLES)}\n")

    print("=== COMBINED DETECTOR: genuinely SAFE emails (false-positive check) ===\n")
    false_positives = 0
    for text, description in SAFE_EXAMPLES:
        result = combined_verdict(text, model, vectorizer)
        verdict = "FLAGGED (false positive!)" if result["flagged"] else "correctly marked safe"
        if result["flagged"]:
            false_positives += 1
        print(f"[{verdict}] {description}")
        if result["reasons"]:
            print(f"    why: {'; '.join(result['reasons'])}")
        print()
    print(f"False positives: {false_positives}/{len(SAFE_EXAMPLES)}")


if __name__ == "__main__":
    run_report()
