const fileInput = document.getElementById("file-input");
const scanFileBtn = document.getElementById("scan-file-btn");
const captureBtn = document.getElementById("capture-btn");
const video = document.getElementById("video");
const qrResult = document.getElementById("qr-result");
const scannedImg = document.getElementById("scanned-img");

let videoStream = null;

// 📌 Scan QR Code from File
scanFileBtn.addEventListener("click", function () {
    const file = fileInput.files[0];
    if (file) {
        const reader = new FileReader();
        reader.onload = function (event) {
            const img = new Image();
            img.src = event.target.result;
            img.onload = function () {
                scannedImg.src = img.src;
                scanQRCode(img);
            };
        };
        reader.readAsDataURL(file);
    } else {
        alert("⚠ Please select an image file.");
    }
});

// 🚀 Capture & Scan: Starts Camera, Captures Image, and Scans QR
captureBtn.addEventListener("click", async function () {
    try {
        // Start camera stream
        videoStream = await navigator.mediaDevices.getUserMedia({ video: { facingMode: "environment" } });
        video.srcObject = videoStream;

        setTimeout(() => {
            captureAndScan();
        }, 1000); // Give camera time to start
    } catch (error) {
        alert("❌ Error accessing camera: " + error.message);
    }
});

function captureAndScan() {
    if (!videoStream) {
        alert("⚠ Camera is not started.");
        return;
    }

    const canvas = document.createElement("canvas");
    canvas.width = video.videoWidth;
    canvas.height = video.videoHeight;
    const ctx = canvas.getContext("2d");
    ctx.drawImage(video, 0, 0, canvas.width, canvas.height);

    // 📸 Display the captured image
    scannedImg.src = canvas.toDataURL();
    scannedImg.style.display = "block"; // Ensure visibility

    // 🔍 Scan the QR code
    scanQRCode(canvas);

    // 🛑 Stop camera after scanning
    videoStream.getTracks().forEach(track => track.stop());
    video.srcObject = null;
    videoStream = null;
}

// 📌 Scan QR Code from Image
function scanQRCode(imageSource) {
    const canvas = document.createElement("canvas");
    const ctx = canvas.getContext("2d");
    canvas.width = imageSource.width || imageSource.videoWidth;
    canvas.height = imageSource.height || imageSource.videoHeight;
    ctx.drawImage(imageSource, 0, 0, canvas.width, canvas.height);
    
    const imageData = ctx.getImageData(0, 0, canvas.width, canvas.height);
    const code = jsQR(imageData.data, canvas.width, canvas.height);
    
    if (code) {
        displayResult(code.data);
    } else {
        qrResult.innerText = "⚠ No QR Code detected.";
    }
}

// 📌 Submit a vote (Malicious or Safe)
async function submitVote(url, voteType) {
    try {
        const response = await fetch("http://localhost:5000/vote", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ url, vote: voteType }),
        });

        const result = await response.json();
        if (result.message) {
            alert("✅ Vote submitted successfully!");

            // 🆕 Update UI instantly
            const maliciousCount = document.getElementById("malicious-count");
            const safeCount = document.getElementById("safe-count");
            if (voteType === "malicious") {
                maliciousCount.innerText = `Malicious: ${parseInt(maliciousCount.innerText.split(": ")[1]) + 1}`;
            } else {
                safeCount.innerText = `Safe: ${parseInt(safeCount.innerText.split(": ")[1]) + 1}`;
            }
        }
    } catch (error) {
        console.error("Error submitting vote:", error);
        alert("❌ Error submitting vote. Please try again.");
    }
}

// 📌 Fetch vote counts for a URL
async function fetchVoteCounts(url) {
    try {
        const response = await fetch(`http://localhost:5000/get-votes?url=${encodeURIComponent(url)}`);
        const data = await response.json();
        
        document.getElementById("malicious-count").innerText = `Malicious: ${data.malicious}`;
        document.getElementById("safe-count").innerText = `Safe: ${data.safe}`;
    } catch (error) {
        console.error("Error fetching vote counts:", error);
    }
}

// 📌 Display Scanned URL & Check Safety
function displayResult(decodedText) {
    qrResult.innerHTML = ""; // ✅ Clear previous results

    if (isValidURL(decodedText)) {
        let url = decodedText;
        if (!url.startsWith("http://") && !url.startsWith("https://")) {
            url = "https://" + url;
        }

        const span = document.createElement("span");
        span.innerText = decodedText;
        span.style.color = "black";
        span.style.textDecoration = "none";
        qrResult.appendChild(span);

        // 🚀 Voting Buttons
        const voteContainer = document.createElement("div");
        voteContainer.innerHTML = `
            <button onclick="submitVote('${url}', 'malicious')" style="background-color:red;">👎 Malicious</button>
            <button onclick="submitVote('${url}', 'safe')" style="background-color:green;">👍 Safe</button>
            <p id="malicious-count">Malicious: 0</p>
            <p id="safe-count">Safe: 0</p>
        `;
        qrResult.appendChild(voteContainer);

        fetchVoteCounts(url); // Load vote counts

        document.getElementById("scan-url-btn").onclick = function () {
            const selectedAPI = document.getElementById("api-choice").value;
            checkURLSafety(decodedText, selectedAPI);
        };

    } else {
        qrResult.innerText = decodedText;
    }
}

// 📌 Validate URL Format
function isValidURL(string) {
    try {
        let url = new URL(string.includes("http") ? string : "https://" + string);
        return url.hostname.includes(".");
    } catch (_) {
        return false;
    }
}

// 📌 Check URL Safety with APIs
async function checkURLSafety(url, api) {
    try {
        const response = await fetch("http://localhost:5000/check-url", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ url, api }),
        });

        const result = await response.json();

        let apiUsed = api === "google" ? "Google Safe Browsing" :
                      api === "virustotal" ? "VirusTotal" :
                      "Random Forest Model"; 

        if (result.status === "MALICIOUS") {
            const userConfirmed = confirm(`⚠ Malicious URL detected! (Checked using ${apiUsed})\nDo you want to visit this link?`);
            if (userConfirmed) {
                window.open(url, "_blank"); // Open in new tab
            }
        } else {
            const userConfirmed = confirm(`✅ Safe URL detected! (Checked using ${apiUsed})\nDo you want to visit this link?`);
            if (userConfirmed) {
                window.open(url, "_blank"); // Open in new tab
            }
        }
    } catch (error) {
        console.error("Error checking URL:", error);
        alert("❌ Error checking the URL. Please try again.");
    }
}