"""
clean_dataset.py
-----------------
Cleans the raw Phishing_Email.csv dataset before use. Fixes found during
inspection:

1. Missing email text (16 rows) - dropped, since an empty email is
   neither a valid "safe" nor "phishing" training example.
2. Extreme outlier rows (e.g. one row was 17 MILLION characters long,
   vs ~880 characters typical) - these are corrupted/malformed rows,
   not real emails. Dropped anything absurdly long that would break or
   skew text processing.
3. Exact duplicate emails (1,112 rows) - removed, so the model doesn't
   just memorize a repeated example and look more accurate than it is.
4. Standardizes column names and labels to something simpler to code
   against: 'text' and 'label' (label is 1 = phishing, 0 = safe).

Run this once - it produces phishing_dataset_clean.csv, which every
other script in this project reads from.
"""

import pandas as pd

RAW_PATH = "Phishing_Email.csv"
CLEAN_PATH = "phishing_dataset_clean.csv"

# A generous upper bound for a "real" email's length. Anything beyond
# this is treated as a corrupted/malformed row, not a genuine outlier
# email (99.9th percentile of real emails here is nowhere near this).
MAX_REASONABLE_LENGTH = 20000


def clean():
    df = pd.read_csv(RAW_PATH)
    start_count = len(df)

    # Standardize column names
    df = df.rename(columns={"Email Text": "text", "Email Type": "label_text"})
    df = df[["text", "label_text"]]

    # 1. Drop missing text
    before = len(df)
    df = df.dropna(subset=["text"])
    print(f"Dropped {before - len(df)} rows with missing email text")

    # 2. Drop corrupted/outlier-length rows
    df["length"] = df["text"].astype(str).str.len()
    before = len(df)
    df = df[df["length"] <= MAX_REASONABLE_LENGTH]
    print(f"Dropped {before - len(df)} rows that were implausibly long "
          f"(> {MAX_REASONABLE_LENGTH} characters) - likely corrupted data")
    df = df.drop(columns=["length"])

    # 3. Drop exact duplicate emails
    before = len(df)
    df = df.drop_duplicates(subset=["text"])
    print(f"Dropped {before - len(df)} duplicate email rows")

    # 4. Standardize label to binary
    df["label"] = (df["label_text"].str.strip().str.lower() == "phishing email").astype(int)
    df = df[["text", "label"]]

    df.to_csv(CLEAN_PATH, index=False)

    print(f"\nStarting rows: {start_count}")
    print(f"Final rows:    {len(df)}")
    print(f"Label balance: {df['label'].value_counts().to_dict()} "
          f"(1 = phishing, 0 = safe)")
    print(f"\nSaved cleaned dataset to {CLEAN_PATH}")


if __name__ == "__main__":
    clean()
