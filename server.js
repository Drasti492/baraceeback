require("dotenv").config();

// Keeps the server alive if an async route throws (safe even if the package is missing).
try { require("express-async-errors"); }
catch {
  console.warn("express-async-errors not installed (run: npm i express-async-errors). Using fallback.");
  process.on("unhandledRejection", e => console.error("Unhandled rejection:", e));
}

const express = require("express");
const mongoose = require("mongoose");
const helmet = require("helmet");
const cors = require("cors");
const path = require("path");
const fs = require("fs");
const http = require("http");
const jwt = require("jsonwebtoken");
const { Server } = require("socket.io");
const rateLimit = require("express-rate-limit");
const User = require("./models/User");

const app = express();
const httpServer = http.createServer(app);
app.set("trust proxy", 1);

const allowedOrigins = (process.env.CLIENT_ORIGIN || "").split(",").map(o => o.trim()).filter(Boolean);
const checkOrigin = (origin, callback) => {
  if (!origin || allowedOrigins.includes(origin)) return callback(null, true);
  return callback(new Error("Origin not allowed by CORS"));
};

app.use(helmet({ crossOriginResourcePolicy: { policy: "cross-origin" } }));
app.use(cors({
  origin: checkOrigin, credentials: false,
  methods: ["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
  allowedHeaders: ["Content-Type", "Authorization"]
}));
app.use(express.json({ limit: "1mb" }));
app.use(express.urlencoded({ extended: true, limit: "1mb" }));

const uploadDir = path.join(__dirname, "uploads");
fs.mkdirSync(uploadDir, { recursive: true });
app.use("/uploads", express.static(uploadDir, { maxAge: "1d" }));

app.use("/api/auth", rateLimit({ windowMs: 15 * 60 * 1000, limit: 30, standardHeaders: true, legacyHeaders: false }));

// extras FIRST (new + fixed routes), then the original routes
app.use("/api", require("./routes/extras"));
app.use("/api", require("./routes/api"));

// Clear JSON 404 for any unknown API route (helps debugging)
app.use("/api", (req, res) => res.status(404).json({ error: `Route not found: ${req.method} ${req.originalUrl}` }));

app.get("/", (_req, res) => res.json({ ok: true, service: "Bara Cee API" }));
app.get("/health", (_req, res) => res.json({ ok: true, service: "Bara Cee API" }));

app.use((err, _req, res, _next) => {
  console.error("API error:", err.message);
  if (err.name === "MulterError") return res.status(400).json({ error: err.message });
  res.status(err.status || 500).json({ error: err.expose ? err.message : "Server error. Please try again." });
});

const io = new Server(httpServer, { cors: { origin: checkOrigin, credentials: false, methods: ["GET", "POST"] } });
app.set("io", io);
const activeUsers = new Map();

io.use(async (socket, next) => {
  try {
    const token = socket.handshake.auth?.token || (socket.handshake.headers.authorization || "").replace(/^Bearer\s+/i, "");
    if (!token) return next(new Error("Authentication required"));
    const payload = jwt.verify(token, process.env.JWT_SECRET);
    if (!payload.sub) return next(new Error("Invalid authentication token"));
    const user = await User.findById(payload.sub).select("_id emailVerified showOnlineStatus showLastSeen isDeactivated");
    if (!user || !user.emailVerified || user.isDeactivated) return next(new Error("Account not authorized"));
    socket.data.userId = String(user._id);
    socket.data.user = user;
    next();
  } catch (error) {
    console.error("Socket authentication failed:", error.message);
    next(new Error("Your session has expired. Please log in again."));
  }
});

function broadcastPresence(user, online, lastSeen = null) {
  if (user.showOnlineStatus === false && user.showLastSeen === false) return;
  const update = { userId: String(user._id) };
  if (user.showOnlineStatus !== false) update.online = online;
  if (user.showLastSeen !== false && lastSeen) update.lastSeen = lastSeen;
  io.emit("presence:update", update);
}

io.on("connection", async socket => {
  const userId = socket.data.userId, user = socket.data.user;
  socket.join(`user:${userId}`);
  let conns = activeUsers.get(userId);
  if (!conns) { conns = new Set(); activeUsers.set(userId, conns); }
  conns.add(socket.id);
  try { await User.updateOne({ _id: userId }, { $set: { online: true } }); }
  catch (e) { console.error("Could not update online status:", e.message); }
  broadcastPresence(user, true);
  socket.emit("socket:ready", { connected: true, userId });

  socket.on("disconnect", async () => {
    const c = activeUsers.get(userId);
    if (!c) return;
    c.delete(socket.id);
    if (c.size === 0) {
      activeUsers.delete(userId);
      const lastSeen = new Date();
      try {
        await User.updateOne({ _id: userId }, { $set: { online: false, lastSeen } });
        broadcastPresence(user, false, lastSeen);
      } catch (e) { console.error("Could not update last seen:", e.message); }
    }
  });
});

const port = process.env.PORT || 5000;
if (!process.env.MONGODB_URI || !process.env.JWT_SECRET) {
  console.error("Missing MONGODB_URI or JWT_SECRET. Check your environment variables.");
  process.exit(1);
}

mongoose.connect(process.env.MONGODB_URI)
  .then(() => {
    console.log("MongoDB connected");
    httpServer.listen(port, "0.0.0.0", () => console.log(`Bara Cee API listening on ${port}`));
  })
  .catch(error => { console.error("MongoDB connection failed:", error.message); process.exit(1); });