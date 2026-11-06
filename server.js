require("dotenv").config();
const express = require("express");
const mongoose = require("mongoose");
const helmet = require("helmet");
const cors = require("cors");
const path = require("path");
const fs = require("fs");
const rateLimit = require("express-rate-limit");

const app = express();
app.set("trust proxy", 1);
app.use(helmet({ crossOriginResourcePolicy: { policy: "cross-origin" } }));
app.use(cors({
  origin: process.env.CLIENT_ORIGIN ? process.env.CLIENT_ORIGIN.split(",").map(x => x.trim()) : true,
  credentials: false
}));
app.use(express.json({ limit: "1mb" }));
app.use(express.urlencoded({ extended: true, limit: "1mb" }));

const uploadDir = path.join(__dirname, "uploads");
fs.mkdirSync(uploadDir, { recursive: true });
app.use("/uploads", express.static(uploadDir, { maxAge: "1d" }));

app.use("/api/auth", rateLimit({ windowMs: 15 * 60 * 1000, limit: 30, standardHeaders: true, legacyHeaders: false }));
app.use("/api", require("./routes/api"));

app.get("/health", (_req, res) => res.json({ ok: true, service: "Bara Cee API" }));
app.use((err, _req, res, _next) => {
  console.error("API error:", err.message);
  if (err.name === "MulterError") return res.status(400).json({ error: err.message });
  res.status(err.status || 500).json({ error: err.expose ? err.message : "Server error. Please try again." });
});

const port = process.env.PORT || 5000;
if (!process.env.MONGODB_URI || !process.env.JWT_SECRET) {
  console.error("Missing MONGODB_URI or JWT_SECRET. Check your environment variables.");
  process.exit(1);
}
mongoose.connect(process.env.MONGODB_URI)
  .then(() => {
    console.log("MongoDB connected");
    app.listen(port, "0.0.0.0", () => console.log(`Bara Cee API listening on ${port}`));
  })
  .catch(err => { console.error("MongoDB connection failed:", err.message); process.exit(1); });
