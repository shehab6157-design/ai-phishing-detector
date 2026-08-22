"""
test_against_ai_phishing.py
-----------------------------
The baseline classifier scored 97% accuracy against OLD-STYLE
spam/phishing (the dataset it was trained on). That number is
misleading on its own - it says nothing about whether it catches
TODAY's threat.

This script feeds it a small set of realistic, well-written,
AI-phishing-style emails - grammatically correct, no spam-trigger
words, referencing plausible real actions - modeled on documented
2026 attack patterns (fake IT password reset, fake invoice request,
fake urgent wire transfer, fake MFA re-enrollment, fake HR document).

None of these use the crude spam patterns (ALL CAPS, "FREE MONEY",
obvious scam phrasing) the baseline learned to detect. If the
baseline's accuracy collapses here, that's the concrete, hands-on
proof of the real gap - not just something we read about.
"""

from baseline_classifier import load_model, predict

# Realistic AI-phishing-style test emails - clean grammar, plausible
# context, no crude spam signals. These are original examples written
# to reflect documented tactics (process-timing exploitation,
# verification-channel bypass, invoice fraud, MFA re-enrollment abuse),
# not copied from any real campaign or source.
AI_STYLE_PHISHING_EXAMPLES = [
    (
        "Hi Sarah, following up on the password reset you requested this "
        "morning. Please confirm your new credentials using the secure link "
        "below within the next hour, as your access will otherwise be "
        "temporarily suspended for security review. Thank you for your "
        "prompt attention. Best regards, IT Support Team",
        "fake IT password reset, references a real recent action"
    ),
    (
        "Hello, attached is the updated invoice for last month's consulting "
        "services. Please process this at your earliest convenience, and "
        "note our banking details have changed since the last payment - "
        "the new account information is included in the attached PDF. Let "
        "me know if you have any questions.",
        "invoice fraud, plausible business tone"
    ),
    (
        "Hi, due to an ongoing system migration, please do not use the "
        "internal ticketing system for this request. I need you to "
        "re-enroll your MFA device today using the link below, as your "
        "current device will lose access at the end of the day. Thanks "
        "for handling this quickly.",
        "MFA re-enrollment abuse, explicit verification-channel bypass"
    ),
    (
        "Hi team, I'm currently in back-to-back meetings and can't take "
        "calls right now. Can you process an urgent wire transfer for the "
        "vendor payment we discussed - details are in the attached "
        "document. Please confirm once it's done so I can update the "
        "client. Thanks so much for the quick turnaround.",
        "executive impersonation, urgency without spam language"
    ),
    (
        "Hello, HR has updated the benefits enrollment document for this "
        "quarter. Please review and sign the attached form before Friday "
        "to avoid any lapse in coverage. Let me know if you have trouble "
        "accessing the document.",
        "fake HR document, low-pressure but time-boxed"
    ),
]


def run_test():
    model, vectorizer = load_model()

    print("=== Testing baseline classifier against AI-phishing-style emails ===\n")
    caught = 0
    for text, description in AI_STYLE_PHISHING_EXAMPLES:
        pred, prob = predict(text, model, vectorizer)
        verdict = "FLAGGED as phishing" if pred == 1 else "MISSED (marked safe)"
        if pred == 1:
            caught += 1
        print(f"[{verdict}]  (phishing probability: {prob:.2f})")
        print(f"  Scenario: {description}")
        print(f"  Email: \"{text[:80]}...\"\n")

    total = len(AI_STYLE_PHISHING_EXAMPLES)
    print(f"Result: caught {caught} of {total} AI-phishing-style emails "
          f"({caught/total*100:.0f}%)")
    print(f"Compare to the {97}% accuracy reported on the OLD-style test set "
          f"the model was trained on - this is the real gap we're trying to close.")


if __name__ == "__main__":
    run_test()
