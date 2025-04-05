require("dotenv").config();
const express = require("express");
const axios = require("axios");
const cors = require("cors");
const crypto = require("crypto");
const mongoose = require("mongoose");

const app = express();
app.use(express.json());
app.use(cors());

const GOOGLE_SAFE_BROWSING_API_KEY = process.env.GOOGLE_SAFE_BROWSING_API_KEY;
const VIRUSTOTAL_API_KEY = process.env.VIRUSTOTAL_API_KEY;
const ML_MODEL_URL = "http://127.0.0.1:5000/check-url"; // Updated to port 5001

// ✅ Connect to MongoDB
mongoose.connect(process.env.MONGODB_URI, {
    useNewUrlParser: true,
    useUnifiedTopology: true,
}).then(() => console.log("✅ Connected to MongoDB"))
  .catch(err => console.error("❌ MongoDB connection error:", err));

const voteSchema = new mongoose.Schema({
    url: { type: String, required: true, unique: true },
    malicious: { type: Number, default: 0 },
    safe: { type: Number, default: 0 },
});

const Vote = mongoose.model("Vote", voteSchema);

// 🔹 API to submit votes
app.post("/vote", async (req, res) => {
    const { url, vote } = req.body;
    if (!url || !vote) return res.status(400).json({ error: "URL and vote required" });

    try {
        let existingVote = await Vote.findOne({ url });

        if (!existingVote) {
            existingVote = new Vote({ url, malicious: 0, safe: 0 });
        }

        if (vote === "malicious") existingVote.malicious += 1;
        else if (vote === "safe") existingVote.safe += 1;

        await existingVote.save();
        res.json({ message: "Vote submitted successfully", votes: existingVote });
    } catch (err) {
        console.error("❌ Error saving vote:", err);
        res.status(500).json({ error: "Failed to store vote" });
    }
});

// 🔹 API to fetch vote counts
app.get("/get-votes", async (req, res) => {
    const { url } = req.query;
    if (!url) return res.status(400).json({ error: "URL required" });

    try {
        const voteData = await Vote.findOne({ url }) || { malicious: 0, safe: 0 };
        res.json(voteData);
    } catch (err) {
        console.error("❌ Error fetching votes:", err);
        res.status(500).json({ error: "Failed to fetch votes" });
    }
});

// ✅ Unified "/check-url" API (Now calling ML Model Correctly)
app.post("/check-url", async (req, res) => {
    const { url, api } = req.body;
    if (!url) return res.status(400).json({ error: "No URL provided" });

    try {
        let result;

        if (api === "google") {
            // ✅ Google Safe Browsing API
            const requestData = {
                client: { clientId: "your-client-name", clientVersion: "1.0" },
                threatInfo: {
                    threatTypes: ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE"],
                    platformTypes: ["ANY_PLATFORM"],
                    threatEntryTypes: ["URL"],
                    threatEntries: [{ url }],
                },
            };

            const response = await axios.post(
                `https://safebrowsing.googleapis.com/v4/threatMatches:find?key=${GOOGLE_SAFE_BROWSING_API_KEY}`,
                requestData
            );

            result = { status: response.data.matches ? "MALICIOUS" : "SAFE", checkedBy: "Google Safe Browsing" };

        } else if (api === "virustotal") {
            // VirusTotal API
            const urlId = crypto.createHash("sha256").update(url).digest("hex");
            const response = await axios.get(`https://www.virustotal.com/api/v3/urls/${urlId}`, {
                headers: { "x-apikey": VIRUSTOTAL_API_KEY },
            });

            const analysis = response.data.data.attributes.last_analysis_stats;
            result = { status: analysis.malicious > 0 ? "MALICIOUS" : "SAFE", checkedBy: "VirusTotal" };

        } else if (api === "ml_model") {
            // ✅ Call Flask ML Model API (Corrected)
            const response = await axios.post(ML_MODEL_URL, { url });

            if (response.data.status) {
                result = {
                    status: response.data.status, // Ensure it's "MALICIOUS" or "SAFE"
                    checkedBy: "Machine Learning Model",
                };
            } else {
                result = { status: "UNKNOWN", checkedBy: "Machine Learning Model", error: "Invalid ML response" };
            }
        } else {
            return res.status(400).json({ error: "Invalid API selection" });
        }

        return res.json(result);

    } catch (error) {
        console.error("❌ Error checking URL:", error.response?.data || error.message);
        return res.status(500).json({ error: "Failed to check URL safety" });
    }
});

// ✅ Start the Node.js Server
app.listen(5000, () => {
    console.log("✅ Node.js server running on port 5000");
});