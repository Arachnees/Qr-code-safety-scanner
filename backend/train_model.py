import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score, classification_report
import joblib
from urllib.parse import urlparse

# Load dataset
data = pd.read_csv('malicious.csv')  # Ensure correct file path

# Check unique labels
print("Unique Labels in Dataset:", data['type'].unique())

# Mapping labels to numerical values dynamically
unique_labels = {label: idx for idx, label in enumerate(data['type'].unique())}
data['label'] = data['type'].map(unique_labels)

# Function to extract features from URLs
def extract_features(url):
    parsed_url = urlparse(url)
    domain = parsed_url.netloc
    path = parsed_url.path
    query = parsed_url.query

    return {
        'url_length': len(url),
        'domain_length': len(domain),
        'path_length': len(path),
        'query_length': len(query),
        'num_special_chars': sum(c in '!@#$%^&*()_+-=[]{}|;:,.<>?/' for c in url),
        'has_https': 1 if parsed_url.scheme == 'https' else 0,
        'num_subdomains': len(domain.split('.')) - 1 if domain else 0,
        'num_slashes': url.count('/'),
        'has_php': 1 if '.php' in url.lower() else 0,
    }

# Extract features
X = pd.DataFrame([extract_features(url) for url in data['url']])
y = data['label']

# Split dataset
X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42, stratify=y)

# Train Random Forest model
model = RandomForestClassifier(n_estimators=100, random_state=42, class_weight='balanced')
model.fit(X_train, y_train)

# Evaluate the model
y_pred = model.predict(X_test)
accuracy = accuracy_score(y_test, y_pred)
print(f"Model Accuracy: {accuracy * 100:.2f}%")

# Classification report
print("Classification Report:")
print(classification_report(y_test, y_pred, target_names=list(unique_labels.keys())))

# Save the model
model_path = "rf_malicious_url.pkl"
joblib.dump(model, model_path)
print(f"Model saved successfully at: {model_path}")
