from flask import Flask, request, jsonify
import joblib
from flask_cors import CORS
from urllib.parse import urlparse
import pandas as pd

app = Flask(__name__)
CORS(app)  # Allow frontend requests

# ✅ Load the trained model
try:
    rf_model = joblib.load("rf_malicious_url.pkl")
    print("Model loaded successfully")
except Exception as e:
    print(f"Error loading model: {e}")
    rf_model = None

label_map = {0: 'benign', 1: 'malware',2:'defacement',3:'phising',4:'safe'}  # Update this based on your dataset
inverse_label_map = {v: k for k, v in label_map.items()}

# ✅ Function to check if a URL is suspicious (same as trainmodel.py)
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

@app.route('/')
def home():
    return "QR Code Safety Scanner API is running!"

@app.route('/check-url', methods=['POST'])
def predict():
    if rf_model is None:
        return jsonify({"error": "Model not loaded properly"}), 500

    try:
        data = request.json
        url = data.get("url")

        if not url:
            return jsonify({"error": "No URL provided"}), 400

        print("Received URL:", url)

        # Extract features from the URL
        url_features = pd.DataFrame([extract_features(url)])

        # Make prediction
        prediction = rf_model.predict(url_features)[0]
        print("Raw Prediction Output:", prediction)

        # Convert numerical prediction to label
        prediction_label = label_map[prediction]
        print("Final Prediction Label:", prediction_label)

        # Return result
        return jsonify({"status": "MALICIOUS" if prediction_label not in ["benign","safe"] else "SAFE"})

    except Exception as e:
        return jsonify({"error": f"Internal server error: {str(e)}"}), 500

if __name__ == '__main__':
    app.run(debug=True)