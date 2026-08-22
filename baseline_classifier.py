"""
baseline_classifier.py
-----------------------
Trains a classic CONTENT-BASED phishing detector: TF-IDF text features
+ Logistic Regression. This is deliberately the "old approach" -
it looks at WHAT the email says (word patterns), not WHO sent it,
WHEN, or HOW it fits the recipient's normal communication.

Why build this first: to have a real, working, honestly-measured
baseline before testing it against modern AI-generated phishing in
test_against_ai_phishing.py. If we skip straight to a fancy detector,
we can't demonstrate - to ourselves or an interviewer - exactly what
gap the newer approach is closing.

Saves the trained model + vectorizer to disk so other scripts can
reuse it without retraining every time.
"""

import pandas as pd
import pickle
from sklearn.model_selection import train_test_split
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import classification_report, confusion_matrix

DATA_PATH = "phishing_dataset_clean.csv"
MODEL_PATH = "baseline_model.pkl"


def train():
    df = pd.read_csv(DATA_PATH)

    X_train, X_test, y_train, y_test = train_test_split(
        df["text"], df["label"], test_size=0.2, random_state=42, stratify=df["label"]
    )

    # TF-IDF: turns email text into word-importance scores.
    # max_features caps vocabulary size to keep this fast and simple.
    vectorizer = TfidfVectorizer(max_features=5000, stop_words="english")
    X_train_vec = vectorizer.fit_transform(X_train)
    X_test_vec = vectorizer.transform(X_test)

    model = LogisticRegression(max_iter=1000)
    model.fit(X_train_vec, y_train)

    predictions = model.predict(X_test_vec)

    print("=== Baseline content-based classifier performance ===\n")
    print(classification_report(y_test, predictions, target_names=["Safe", "Phishing"]))
    print("Confusion matrix (rows=actual, cols=predicted):")
    print(confusion_matrix(y_test, predictions))

    # Save both the model and vectorizer together
    with open(MODEL_PATH, "wb") as f:
        pickle.dump({"model": model, "vectorizer": vectorizer}, f)
    print(f"\nModel saved to {MODEL_PATH}")

    return model, vectorizer


def load_model():
    with open(MODEL_PATH, "rb") as f:
        saved = pickle.load(f)
    return saved["model"], saved["vectorizer"]


def predict(text, model, vectorizer):
    vec = vectorizer.transform([text])
    pred = model.predict(vec)[0]
    prob = model.predict_proba(vec)[0][1]  # probability of being phishing
    return pred, prob


if __name__ == "__main__":
    train()
