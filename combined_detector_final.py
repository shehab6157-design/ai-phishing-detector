"""
combined_detector_final.py
----------------------------
Final, consolidated version of the AI-phishing detector. Replaces
combined_detector.py and combined_detector_v2.py with a single clean
script — same logic as v2 (the version that closed the last gaps),
just no longer split across two files with an in-between iteration.

Three independent signals are combined into one verdict:

1. BASELINE CONTENT MODEL (baseline_classifier.py)
   TF-IDF + Logistic Regression trained on 17,450 cleaned emails.
   97% accuracy on old-style spam/phishing, but 0/5 on realistic
   AI-generated phishing — it only knows what OLD phishing looks like.

2. BEHAVIORAL SIGNAL DETECTOR (behavioral_detector.py)
   Regex-based detection of what the email is asking the reader to DO
   (bypass verification, urgent deadline, credential/financial request,
   click/sign something) rather than how it's worded. Catches 4/5 of
   what the baseline misses. Risk = LOW / MEDIUM / HIGH based on how
   many categories co-occur.

3. SENDER HISTORY (sender_history.py)
   Simulated mailbox relationship data (since the dataset has no
   sender metadata). Catches the two cases that survive both of the
   above: low-pressure, well-written social engineering (invoice
   fraud with no urgency, a fake facilities/badge request) — where
   the giveaway isn't the wording, it's that this specific sender
   has no real relationship with the mailbox.

FINAL VERDICT — flagged if ANY of the following is true:
  - baseline confidence >= 0.85
  - behavioral risk is MEDIUM or HIGH
  - behavioral risk is LOW (exactly one soft signal) AND the sender
    is unknown or on an unrecognized/lookalike domain

Result on the 12 phishing / 12 safe expanded test set: 10/12 phishing
caught (83%), 0/12 false positives, after sender-history closed the
final two misses.
"""

from baseline_classifier import load_model, predict as baseline_predict
from behavioral_detector import analyze as behavioral_analyze
from sender_history import check_sender

BASELINE_CONFIDENCE_THRESHOLD = 0.85


def combined_verdict(text, sender_address, model, vectorizer):
    """
    Returns the final verdict for one email.

    sender_address is required — the sender-history signal is part of
    the core logic now, not an optional extra. Pass "unknown@unknown"
    (or any address with no history) if the sender is genuinely unknown.
    """
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

    return {
        "flagged": final_flag,
        "baseline_prob": baseline_prob,
        "behavioral_risk": behavioral_result["risk"],
        "sender_risk": sender_result["risk_contribution"],
        "reasons": reasons,
    }


if __name__ == "__main__":
    model, vectorizer = load_model()

    test_cases = [
        (
            "Hello, attached is the updated invoice for last month's "
            "consulting services. Please process this at your earliest "
            "convenience, and note our banking details have changed "
            "since the last payment.",
            "vendor-billing@acme-consuIting.com",  # lookalike domain
            "invoice fraud, no urgency",
        ),
        (
            "Hi, I noticed your badge access wasn't updated after the "
            "office move. Please re-verify your employee ID and department "
            "using the form below so facilities can restore full access.",
            "facilities-updates@ourcompany.com",  # unrecognized address
            "fake facilities/badge request",
        ),
        (
            "Hi Maria, attached is the invoice for October's contractor "
            "hours as discussed on our call. No change to our usual "
            "payment details.",
            "vendor-billing@acmeconsulting.com",  # exact known contact
            "genuinely safe invoice from a known vendor",
        ),
    ]

    print("=== Combined detector (final) — sample verdicts ===\n")
    for text, sender, description in test_cases:
        result = combined_verdict(text, sender, model, vectorizer)
        verdict = "FLAGGED" if result["flagged"] else "not flagged"
        print(f"[{verdict}] {description}")
        print(f"  sender: {sender}")
        if result["reasons"]:
            print(f"  why: {'; '.join(result['reasons'])}")
        print()
