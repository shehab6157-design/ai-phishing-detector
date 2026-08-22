"""
behavioral_detector.py
------------------------
The baseline TF-IDF model looks at WORD PATTERNS learned from old spam.
It caught 0 of 5 realistic AI-phishing-style emails because those
emails don't contain old spam patterns - they're clean, well-written,
professional-sounding.

This detector instead looks for BEHAVIORAL SIGNALS that stay present
regardless of how well-written the email is - because they're about
what the email is asking the reader to DO, not how it's worded:

1. VERIFICATION_BYPASS - explicitly discourages the recipient from
   using their organization's normal verification process
   (e.g. "don't use the ticketing system", "respond directly instead")
2. URGENCY - time pressure combined with a consequence
   (e.g. "within the hour", "before your access is suspended")
3. CREDENTIAL_OR_ACCESS_REQUEST - asks to reset/confirm/re-enroll
   credentials, MFA, or account access
4. FINANCIAL_REQUEST - asks to process payment, wire transfer, invoice,
   or change banking details
5. ATTACHMENT_OR_LINK_ACTION - asks the reader to click/open/sign
   something, combined with any of the above

Each email gets a score based on how many of these fire together -
deliberately not just "one keyword = phishing", since e.g. "urgent"
alone appears in plenty of legitimate email too. The combination is
what matters, mirroring how real behavioral email security tools work.
"""

import re

VERIFICATION_BYPASS_PATTERNS = [
    r"don'?t use the (ticketing|normal|usual|internal) (system|process|channel)",
    r"respond directly",
    r"please do not (use|go through)",
    r"outside (the|our) (usual|normal) (process|channel)",
    r"due to (system|technical) issues?,? (please )?(do not|don'?t)",
]

URGENCY_PATTERNS = [
    r"within (the|an?) (hour|day|24 hours|few hours)",
    r"(will be|otherwise) (suspended|locked|disabled|terminated)",
    r"immediately",
    r"urgent(ly)?",
    r"before (the )?(end of (the )?day|friday|today|tomorrow)",
    r"as soon as possible",
    r"asap",
]

CREDENTIAL_ACCESS_PATTERNS = [
    r"reset (your )?(password|credentials)",
    r"confirm your (new )?(credentials|password|account)",
    r"re-?enroll (your )?(mfa|device|authentication)",
    r"(re-?)?verify your (account|identity|access|employee id|badge|department)",
    r"lose access",
    r"restore (your )?(full )?access",
]

FINANCIAL_PATTERNS = [
    r"wire transfer",
    r"process (this|the) (payment|invoice)",
    r"banking (details|information) (have )?changed",
    r"updated invoice",
    r"vendor payment",
]

ACTION_PATTERNS = [
    r"click (the|this) (link|button)",
    r"open the attached",
    r"sign (the|this) (attached )?(form|document)",
    r"secure link below",
]


def _count_matches(text, patterns):
    text_lower = text.lower()
    hits = []
    for p in patterns:
        if re.search(p, text_lower):
            hits.append(p)
    return hits


def analyze(text):
    """Returns a dict of which signal categories fired, and an overall score."""
    signals = {
        "verification_bypass": _count_matches(text, VERIFICATION_BYPASS_PATTERNS),
        "urgency": _count_matches(text, URGENCY_PATTERNS),
        "credential_or_access_request": _count_matches(text, CREDENTIAL_ACCESS_PATTERNS),
        "financial_request": _count_matches(text, FINANCIAL_PATTERNS),
        "attachment_or_link_action": _count_matches(text, ACTION_PATTERNS),
    }

    categories_fired = sum(1 for hits in signals.values() if hits)

    # Scoring logic: any single category alone is common in legitimate
    # email (e.g. "urgent" shows up in real work emails constantly).
    # Risk comes from COMBINATIONS - e.g. urgency + credential request,
    # or verification bypass + financial request.
    if categories_fired >= 3:
        risk = "HIGH"
    elif categories_fired == 2:
        risk = "MEDIUM"
    elif categories_fired == 1:
        risk = "LOW"
    else:
        risk = "NONE"

    return {
        "risk": risk,
        "categories_fired": categories_fired,
        "signals": signals,
    }


def explain(result):
    lines = [f"Risk: {result['risk']} ({result['categories_fired']} signal categories fired)"]
    for category, hits in result["signals"].items():
        if hits:
            lines.append(f"  - {category}: matched {len(hits)} pattern(s)")
    return "\n".join(lines)


if __name__ == "__main__":
    # Quick self-test using the same 5 emails the baseline missed
    from test_against_ai_phishing import AI_STYLE_PHISHING_EXAMPLES

    print("=== Behavioral detector vs. the 5 emails the baseline MISSED ===\n")
    for text, description in AI_STYLE_PHISHING_EXAMPLES:
        result = analyze(text)
        print(f"Scenario: {description}")
        print(explain(result))
        print()
