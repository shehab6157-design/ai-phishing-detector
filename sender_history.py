"""
sender_history.py
--------------------
Our dataset (Phishing_Email.csv) has no sender/timestamp columns -
just email text and a label. Real behavioral email security relies
heavily on sender relationship history (has this address emailed this
recipient before, how often, does it match a known vendor/domain).

Since that data doesn't exist for us, this file simulates a small,
realistic "known contacts" address book for one fictional employee -
similar in spirit to simulate.py in the lateral-movement project: a
stand-in for real data, built so the DETECTION LOGIC can be tested and
demonstrated honestly, without pretending we have real inbox history
we don't have.

In a real deployment, this data would come from actual mail server
logs (which senders has this mailbox exchanged mail with, how many
times, over what time period) - not from a manually written list.
"""

# Simulates the sender history of one employee's mailbox: which
# sender addresses/domains they have a real ongoing relationship with.
KNOWN_CONTACTS = {
    "vendor-billing@acmeconsulting.com": {"emails_exchanged": 14, "known_since_days": 210},
    "hr@ourcompany.com": {"emails_exchanged": 32, "known_since_days": 400},
    "it-support@ourcompany.com": {"emails_exchanged": 8, "known_since_days": 400},
    "maria.chen@ourcompany.com": {"emails_exchanged": 56, "known_since_days": 380},
    "facilities@ourcompany.com": {"emails_exchanged": 3, "known_since_days": 400},
    "legal@ourcompany.com": {"emails_exchanged": 6, "known_since_days": 400},
}

KNOWN_DOMAINS = set(addr.split("@")[1] for addr in KNOWN_CONTACTS)


def check_sender(sender_address):
    """
    Returns a risk assessment for a given sender address based on
    simulated relationship history.
    """
    if sender_address in KNOWN_CONTACTS:
        history = KNOWN_CONTACTS[sender_address]
        return {
            "known": True,
            "risk_contribution": "NONE",
            "reason": (f"Known contact - {history['emails_exchanged']} prior emails "
                       f"over {history['known_since_days']} days."),
        }

    domain = sender_address.split("@")[-1] if "@" in sender_address else ""
    if domain in KNOWN_DOMAINS:
        return {
            "known": False,
            "risk_contribution": "LOW",
            "reason": (f"Domain '{domain}' has known contacts, but this specific "
                       f"address ({sender_address}) has never emailed before - "
                       f"could be a new colleague, or could be spoofing a trusted domain."),
        }

    return {
        "known": False,
        "risk_contribution": "MEDIUM",
        "reason": f"'{sender_address}' has no prior relationship and is on an unrecognized domain.",
    }


if __name__ == "__main__":
    test_senders = [
        "maria.chen@ourcompany.com",       # known contact
        "hr-updates@ourcompany.com",       # known domain, new address
        "vendor-billing@acme-consuIting.com",  # lookalike domain (capital I instead of l)
        "random-sender@totally-unknown.net",   # fully unknown
    ]
    for s in test_senders:
        result = check_sender(s)
        print(f"{s}\n  -> {result['risk_contribution']}: {result['reason']}\n")
