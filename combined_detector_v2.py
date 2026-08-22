"""
combined_detector_v2.py
--------------------------
Adds sender-history (sender_history.py) as a THIRD signal alongside
the baseline content model and the behavioral phrase detector.

Why this closes the remaining gap: the two phishing emails that
survived every previous version (invoice fraud with no urgency,
facilities/badge request) share one thing - they're LOW PRESSURE,
socially engineered to sound like routine business-as-usual. No
amount of phrase-matching catches "this is just normal" written
convincingly. What they can't fake as easily is an actual prior
relationship with this specific mailbox.

Final verdict logic (each condition alone is enough to flag):
  - baseline content model very confident (>= 0.85), OR
  - behavioral risk is MEDIUM or HIGH on its own, OR
  - behavioral risk is LOW (1 category) AND sender is unknown/risky
    (this is the new rule: a single soft signal + an unverified
    sender is more suspicious than either alone)
"""

from baseline_classifier import load_model, predict as baseline_predict
from behavioral_detector import analyze as behavioral_analyze
from sender_history import check_sender

BASELINE_CONFIDENCE_THRESHOLD = 0.85


def combined_verdict_v2(text, sender_address, model, vectorizer):
    _, baseline_prob = baseline_predict(text, model, vectorizer)
    behavioral_result = behavioral_analyze(text)
    sender_result = check_sender(sender_address)

    baseline_flag = baseline_prob >= BASELINE_CONFIDENCE_THRESHOLD
    behavioral_flag = behavioral_result["risk"] in ("MEDIUM", "HIGH")
    soft_behavioral = behavioral_result["risk"] == "LOW"
    sender_risky = sender_result["risk_contribution"] in ("LOW", "MEDIUM")

    combo_flag = soft_behavioral and sender_risky

    final_flag = baseline_flag or behavioral_flag or combo_flag

    reasons = []
    if baseline_flag:
        reasons.append(f"baseline confidence {baseline_prob:.2f}")
    if behavioral_flag:
        fired = [k for k, v in behavioral_result["signals"].items() if v]
        reasons.append(f"behavioral risk {behavioral_result['risk']} ({', '.join(fired)})")
    if combo_flag:
        reasons.append(f"soft behavioral signal + sender risk: {sender_result['reason']}")

    return {"flagged": final_flag, "reasons": reasons}


if __name__ == "__main__":
    model, vectorizer = load_model()

    # The two cases that survived every previous version, now with a
    # sender address attached (simulating a first-time/unverified sender)
    test_cases = [
        (
            "Hello, attached is the updated invoice for last month's "
            "consulting services. Please process this at your earliest "
            "convenience, and note our banking details have changed "
            "since the last payment.",
            "vendor-billing@acme-consuIting.com",  # lookalike domain
            "invoice fraud, no urgency - previously MISSED"
        ),
        (
            "Hi, I noticed your badge access wasn't updated after the "
            "office move. Please re-verify your employee ID and department "
            "using the form below so facilities can restore full access.",
            "facilities-updates@ourcompany.com",  # unrecognized specific address
            "fake facilities/badge request - previously MISSED"
        ),
        (
            "Hi Maria, attached is the invoice for October's contractor "
            "hours as discussed on our call. No change to our usual "
            "payment details.",
            "vendor-billing@acmeconsulting.com",  # exact known contact
            "genuinely safe invoice from a known vendor - should NOT flag"
        ),
    ]

    for text, sender, description in test_cases:
        result = combined_verdict_v2(text, sender, model, vectorizer)
        verdict = "FLAGGED" if result["flagged"] else "missed/safe"
        print(f"[{verdict}] {description}")
        print(f"  sender: {sender}")
        if result["reasons"]:
            print(f"  why: {'; '.join(result['reasons'])}")
        print()
