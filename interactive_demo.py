"""
interactive_demo.py
----------------------
Live, real-time demo of the final combined detector. No cloud, no
server - just run this locally and paste in an email as you (or
someone watching) type it, and get an instant verdict with the
reasoning behind it.

Good for: showing the project live in an interview or screen-share,
without needing to deploy anything.

Usage:
    python3 interactive_demo.py

Then follow the prompts: paste the email body, press Enter twice to
submit it, enter a sender address (or leave blank to simulate an
unknown sender), and see the verdict immediately.
"""

from baseline_classifier import load_model
from combined_detector_final import combined_verdict


def read_multiline(prompt):
    print(prompt)
    print("(Paste the email text, then press Enter on an empty line to submit)")
    lines = []
    while True:
        line = input()
        if line == "":
            break
        lines.append(line)
    return " ".join(lines)


def main():
    print("Loading model...")
    model, vectorizer = load_model()
    print("Ready.\n")
    print("=" * 60)
    print("  AI-Phishing Detector — Live Demo")
    print("=" * 60)

    while True:
        text = read_multiline("\nPaste the email text:")
        if not text.strip():
            print("No text entered — try again, or Ctrl+C to quit.")
            continue

        sender = input(
            "\nSender email address (leave blank to simulate an unknown/unverified sender): "
        ).strip()
        if not sender:
            sender = "unverified-sender@external-domain.net"

        result = combined_verdict(text, sender, model, vectorizer)

        print("\n" + "-" * 60)
        verdict = "FLAGGED AS PHISHING" if result["flagged"] else "NOT FLAGGED (looks safe)"
        print(f"VERDICT: {verdict}")
        print(f"  baseline content-model confidence: {result['baseline_prob']:.2f}")
        print(f"  behavioral risk:                    {result['behavioral_risk']}")
        print(f"  sender risk:                         {result['sender_risk']}")
        if result["reasons"]:
            print("  reasons:")
            for r in result["reasons"]:
                print(f"    - {r}")
        print("-" * 60)

        again = input("\nTest another email? (y/n): ").strip().lower()
        if again != "y":
            print("Done.")
            break


if __name__ == "__main__":
    main()
