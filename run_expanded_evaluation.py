"""
run_expanded_evaluation.py
-----------------------------
Runs the combined detector (combined_detector.py) against the larger
test set (expanded_test_set.py) - 12 phishing + 12 safe examples
instead of the original 5 + 4 - to get a more solid read on real
performance before adding more complexity to the project.
"""

from baseline_classifier import load_model
from combined_detector import combined_verdict
from expanded_test_set import EXPANDED_PHISHING_EXAMPLES, EXPANDED_SAFE_EXAMPLES


def run():
    model, vectorizer = load_model()

    print("=== EXPANDED EVALUATION: phishing examples ===\n")
    caught = 0
    missed_list = []
    for text, description in EXPANDED_PHISHING_EXAMPLES:
        result = combined_verdict(text, model, vectorizer)
        verdict = "FLAGGED" if result["flagged"] else "missed"
        if result["flagged"]:
            caught += 1
        else:
            missed_list.append(description)
        print(f"[{verdict}] {description}")

    total_phishing = len(EXPANDED_PHISHING_EXAMPLES)
    print(f"\nPhishing caught: {caught}/{total_phishing} "
          f"({caught/total_phishing*100:.0f}%)")
    if missed_list:
        print("Missed:")
        for m in missed_list:
            print(f"  - {m}")

    print("\n=== EXPANDED EVALUATION: genuinely safe examples ===\n")
    false_positives = 0
    fp_list = []
    for text, description in EXPANDED_SAFE_EXAMPLES:
        result = combined_verdict(text, model, vectorizer)
        verdict = "FLAGGED (false positive!)" if result["flagged"] else "correctly safe"
        if result["flagged"]:
            false_positives += 1
            fp_list.append(description)
        print(f"[{verdict}] {description}")

    total_safe = len(EXPANDED_SAFE_EXAMPLES)
    print(f"\nFalse positives: {false_positives}/{total_safe} "
          f"({false_positives/total_safe*100:.0f}%)")
    if fp_list:
        print("False-positive cases:")
        for f in fp_list:
            print(f"  - {f}")


if __name__ == "__main__":
    run()
