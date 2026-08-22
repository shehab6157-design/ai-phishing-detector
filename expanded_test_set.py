"""
expanded_test_set.py
-----------------------
The first test (5 phishing + 4 safe) was a good proof of concept, but
too small to trust the percentages on their own. This expands both
sets to give a more solid read on the combined detector's real
performance before we add more complexity (like sender-history).

All examples here are ORIGINAL, written to reflect documented 2026
attack patterns and normal workplace email tone - none are copied
from any real source.
"""

# 12 realistic AI-phishing-style emails, spanning different attack
# types and different levels of urgency (including deliberately subtle
# ones, to stress-test the detector honestly rather than make it look
# artificially good).
EXPANDED_PHISHING_EXAMPLES = [
    (
        "Hi Sarah, following up on the password reset you requested this "
        "morning. Please confirm your new credentials using the secure link "
        "below within the next hour, as your access will otherwise be "
        "temporarily suspended for security review.",
        "fake IT password reset"
    ),
    (
        "Hello, attached is the updated invoice for last month's consulting "
        "services. Please process this at your earliest convenience, and "
        "note our banking details have changed since the last payment.",
        "invoice fraud, no urgency language"
    ),
    (
        "Hi, due to an ongoing system migration, please do not use the "
        "internal ticketing system for this request. I need you to "
        "re-enroll your MFA device today, as your current device will "
        "lose access at the end of the day.",
        "MFA re-enrollment abuse"
    ),
    (
        "Hi team, I'm currently in back-to-back meetings and can't take "
        "calls right now. Can you process an urgent wire transfer for the "
        "vendor payment we discussed - details are in the attached "
        "document. Please confirm once it's done.",
        "executive impersonation"
    ),
    (
        "Hello, HR has updated the benefits enrollment document for this "
        "quarter. Please review and sign the attached form before Friday "
        "to avoid any lapse in coverage.",
        "fake HR document"
    ),
    (
        "Your mailbox is nearly full and new messages will start bouncing "
        "within 24 hours. Click here to verify your account and increase "
        "your storage quota immediately.",
        "fake mailbox-quota urgency"
    ),
    (
        "Hi, this is a follow-up on the shared document I sent yesterday. "
        "Please open the attached file and confirm you can access it before "
        "our call this afternoon, as I won't be able to resend it after "
        "today.",
        "fake shared-document lure with soft urgency"
    ),
    (
        "Finance flagged a discrepancy on a recent transaction tied to your "
        "account. To avoid a hold being placed, please confirm your account "
        "details using the link below as soon as possible.",
        "fake finance/account verification"
    ),
    (
        "Hi, I noticed your badge access wasn't updated after the office "
        "move. Please re-verify your employee ID and department using the "
        "form below so facilities can restore full access.",
        "fake facilities/badge access request"
    ),
    (
        "Reminder: your calendar shows a client call in 15 minutes. Please "
        "review the attached briefing document and confirm the dial-in "
        "details before joining, as the line will not be held past start "
        "time.",
        "fake meeting-briefing lure, time pressure"
    ),
    (
        "Hi, legal needs your signature on the attached NDA before the "
        "partnership announcement goes out tomorrow morning. Please sign "
        "and return today - we can't delay the announcement.",
        "fake legal document, hard deadline"
    ),
    (
        "Your subscription renewal failed due to an expired payment method. "
        "Update your billing details within 24 hours to avoid service "
        "interruption.",
        "fake billing/subscription urgency"
    ),
]

# 12 genuinely safe, everyday emails - deliberately including ones that
# mention money, deadlines, documents, or account topics, since those
# words alone shouldn't trigger a false alarm.
EXPANDED_SAFE_EXAMPLES = [
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
        "as discussed on our call. No change to our usual payment details.",
        "routine invoice, confirms no change to payment details"
    ),
    (
        "Quick heads up - the client asked if we could turn around the "
        "draft by end of day Friday instead of next week. Should be doable "
        "but let me know if that's a problem for your part.",
        "normal deadline pressure, no money/credentials involved"
    ),
    (
        "Thanks for the update on the migration. No action needed on my "
        "end for now - I'll follow up once QA finishes their pass.",
        "routine status update"
    ),
    (
        "Hi, could you sign off on the NDA whenever you get a chance this "
        "week? No rush, legal just needs it filed before the quarter closes.",
        "routine document request, explicitly no rush"
    ),
    (
        "Hey, are you free for a quick call this afternoon to go over the "
        "budget numbers before I send them to finance tomorrow?",
        "normal internal coordination"
    ),
    (
        "Just confirming I received the briefing doc for tomorrow's client "
        "call - looks good, see you there.",
        "routine confirmation, mentions meeting/briefing"
    ),
    (
        "Hi, wanted to flag that the vendor payment for last month cleared "
        "fine on our end - no issues to report.",
        "routine payment confirmation, no request"
    ),
    (
        "Hi, HR sent the updated benefits doc earlier - I already signed "
        "mine, just a heads up in case you hadn't seen it yet.",
        "casual peer heads-up about a real HR document"
    ),
    (
        "Reminder from IT: scheduled maintenance this weekend, no action "
        "needed, systems will be briefly unavailable Saturday night.",
        "routine IT maintenance notice, no request"
    ),
    (
        "Hey, badge access for the new office wing should be live for "
        "everyone by Monday - let facilities know if yours doesn't work.",
        "routine facilities update"
    ),
]
