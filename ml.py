import pandas as pd
import numpy as np
from sklearn.model_selection import train_test_split
from sklearn.feature_extraction.text import CountVectorizer
from sklearn.naive_bayes import MultinomialNB
import joblib

# === import Dataset ===
df = pd.read_csv("spam.csv", encoding='ISO-8859-1')[['Category', 'Message']]  # Keep only necessary columns
df.groupby('Category').describe()
# === Label Encoding: ham → 0, spam → 1 ===
df['label'] = df['Category'].apply(lambda x: 1 if x == 'spam' else 0)

# === Train-Test Split ===
x_train, x_test, y_train, y_test = train_test_split(
    df['Message'], df['label'], test_size=0.1, stratify=df['label'], random_state=42
)

# === Vectorization : find the word count and save it as a matrix===
vectorizer = CountVectorizer()
x_train_vec = vectorizer.fit_transform(x_train)
x_test_vec = vectorizer.transform(x_test)

# === Model Training ===
model = MultinomialNB()
model.fit(x_train_vec, y_train)

# === Model Evaluation ===
accuracy = model.score(x_test_vec, y_test)
print(f"Model trained with accuracy: {accuracy:.2%}")

# === Save Model and Vectorizer ===
joblib.dump(model, "spam_model.pkl")
joblib.dump(vectorizer, "vectorizer.pkl")
print(" Model and vectorizer saved successfully.")
