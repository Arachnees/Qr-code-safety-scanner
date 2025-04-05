# 🛡️ QR Code Safety Scanner

A smart QR code scanner that checks if the embedded URL is **malicious** or **safe** using AI, APIs, and community feedback.

---

🎯 Objective
The QR Code Safety Scanner is a full-stack web application designed to scan QR codes and safely verify the URLs they contain. With the rise of QR codes in everyday use — from restaurant menus to payment gateways — malicious actors have started embedding phishing or malware URLs within them.
This project aims to prevent users from opening harmful URLs by combining:
✅ Trusted security APIs
🤖 A Machine Learning (ML) model
👥 Real-time community feedback


## 🚀 Features

- 📷 Scan QR codes using webcam
- 🔗 Extract and display the embedded link
- ✅ Three-step verification:
  1. VirusTotal API
  2. Google Safe Browsing API
  3. AI model (Random Forest classifier)
- 👥 Community voting: Mark links as safe/malicious
- 📊 Analytics Dashboard:
  - Total scans
  - Safe vs malicious stats
  - Most reported links
- 🧠 Model used: Random Forest (`rf_malicious_url.pkl`)
- 🌱 Minimalist UI with easy navigation

---

---

## 📂 Dataset

This project uses a dataset of **10,000 URLs** labeled as *malicious* or *safe* to train the ML model.

- 📁 File: `malicious.csv`
- 📊 Used to train the Random Forest model
- 🧠 Features include URL length, structure, presence of special characters, etc.

> ⚠️ For research and educational purposes only.

---

## 🤖 Trained Model

- File: `rf_malicious_url.pkl`
- Algorithm: Random Forest
- Purpose: Classifies a URL as **safe** or **malicious** after scanning.
- Automatically loaded during QR scan for quick predictions.
-It will be created automatically when the model is trained.

📊 Dashboard Features (Future Scope or Already Added)
✅ Total scanned QR codes
📉 Count of safe vs malicious URLs
🔝 Most reported malicious links
🗳️ Voting summary (thumbs up/down)

📌 Tech Stack
Frontend: HTML, CSS, JavaScript
Backend: Node.js + Python
Database: MongoDB
AI/ML: Random Forest Classifier
APIs Used:
VirusTotal
Google Safe Browsing

🧩 How It Works – Step by Step
Scan QR Code
Users click “Start Camera” and “Scan QR Code.”
The webcam captures the image and extracts the QR code using jsQR.
Extract Embedded URL
The scanner decodes the QR and displays the extracted URL.
Three-Step URL Verification Process:

🔍 Step 1: VirusTotal API Check
The URL is sent to VirusTotal to check if it has been reported or detected by antivirus vendors as malicious.
🛡️ Step 2: Google Safe Browsing API Check
The URL is verified against Google’s blacklists for phishing and malware sites.
🧠 Step 3: AI-based Classification
A trained Random Forest model (rf_malicious_url.pkl) analyzes URL features like:
Length
Presence of suspicious characters
Use of IP addresses or misspelled domains
HTTPS status
Based on these features, it predicts whether the URL is safe or malicious.
User Decision & Voting
The scanner shows the result and gives users two buttons:
👍 Safe  👎 Malicious
Clicking a button will update the stored result in the MongoDB database.

Report Display
If the URL was scanned earlier, it shows:
✅ Safety status (based on majority voting or past report)
🧮 Number of “safe” and “malicious” votes


📄 License
This project is licensed under the MIT License
