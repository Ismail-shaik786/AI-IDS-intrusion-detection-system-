import pandas as pd
import numpy as np
import glob

from sklearn.preprocessing import LabelEncoder
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier

from sklearn.metrics import (
    accuracy_score,
    classification_report,
    confusion_matrix
)

import joblib

# Load all CSV files
files = glob.glob("../dataset/*.csv")

dataframes = []

print("Loading CSV Files...\n")

for file in files:
    try:
        df = pd.read_csv(file)

        # Clean column names
        df.columns = df.columns.str.strip()

        dataframes.append(df)

        print(f"Loaded: {file}")

    except Exception as e:
        print(f"Error loading {file}: {e}")

# Combine all datasets
data = pd.concat(dataframes, ignore_index=True)

print("\nAll Datasets Combined Successfully")

# Replace Infinity values
data.replace([np.inf, -np.inf], np.nan, inplace=True)

# Remove NaN rows
data.dropna(inplace=True)

print("\nDataset Cleaned Successfully")

# Show labels
print("\nAttack Labels:")
print(data['Label'].value_counts())

# Encode labels
encoder = LabelEncoder()

data['Label'] = encoder.fit_transform(data['Label'])

print("\nLabels Encoded Successfully")

# Features and labels
X = data.drop('Label', axis=1)

y = data['Label']

print("\nFeatures Shape:", X.shape)
print("Labels Shape:", y.shape)

# Split dataset
X_train, X_test, y_train, y_test = train_test_split(
    X,
    y,
    test_size=0.2,
    random_state=42
)

print("\nTraining AI Model...\n")

# Train model
model = RandomForestClassifier(
    n_estimators=100,
    random_state=42,
    n_jobs=-1
)

model.fit(X_train, y_train)

print("Model Training Completed")

# Predictions
y_pred = model.predict(X_test)

# Accuracy
accuracy = accuracy_score(y_test, y_pred)

print("\nModel Accuracy:")
print(accuracy)

# Classification Report
print("\nClassification Report:")
print(classification_report(y_test, y_pred))

# Confusion Matrix
print("\nConfusion Matrix:")
print(confusion_matrix(y_test, y_pred))

# Save model
joblib.dump(model, "../models/multi_ids_model.pkl")

print("\nMulti-Class IDS Model Saved Successfully")