require("dotenv").config();
require("express-async-errors");

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

const allowedOrigins = (process.env.CLIENT_ORIGIN || "")
  .split(",")
  .map(origin => origin.trim())
  .filter(Boolean);

const checkOrigin = (origin, callback) => {
  if (!origin || allowedOrigins.includes(origin)) {
    return callback(null, true);
  }

  return callback(new Error("Origin not allowed by CORS"));
};

// Existing Express security and CORS
app.use(helmet({
  crossOriginResourcePolicy: { policy: "cross-origin" }
}));

app.use(cors({
  origin: checkOrigin,
  credentials: false,
  methods: ["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
  allowedHeaders: ["Content-Type", "Authorization"]
}));

app.use(express.json({ limit: "1mb" }));
app.use(express.urlencoded({ extended: true, limit: "1mb" }));

// Uploads
const uploadDir = path.join(__dirname, "uploads");
fs.mkdirSync(uploadDir, { recursive: true });

app.use("/uploads", express.static(uploadDir, {
  maxAge: "1d"
}));

// Existing API routes and rate limiting
app.use(
  "/api/auth",
  rateLimit({
    windowMs: 15 * 60 * 1000,
    limit: 30,
    standardHeaders: true,
    legacyHeaders: false
  })
);



app.get("/health", (_req, res) => {
  res.json({ ok: true, service: "Bara Cee API" });
});

// Existing Express error handler
app.use((err, _req, res, _next) => {
  console.error("API error:", err.message);

  if (err.name === "MulterError") {
    return res.status(400).json({ error: err.message });
  }

  res.status(err.status || 500).json({
    error: err.expose
      ? err.message
      : "Server error. Please try again."
  });
});

// Socket.IO
const io = new Server(httpServer, {
  cors: {
    origin: checkOrigin,
    credentials: false,
    methods: ["GET", "POST"]
  }
});

// Make Socket.IO accessible to Express routes later
app.set("io", io);

// Track multiple connections for the same user
const activeUsers = new Map();

// Authenticate every socket using the existing JWT
io.use(async (socket, next) => {
  try {
    const authToken = socket.handshake.auth?.token;

    const headerToken = (
      socket.handshake.headers.authorization || ""
    ).replace(/^Bearer\s+/i, "");

    const token = authToken || headerToken;

    if (!token) {
      return next(new Error("Authentication required"));
    }

    const payload = jwt.verify(token, process.env.JWT_SECRET);

    if (!payload.sub) {
      return next(new Error("Invalid authentication token"));
    }

    const user = await User.findById(payload.sub).select(
      "_id emailVerified showOnlineStatus showLastSeen isDeactivated"
    );

    if (!user || !user.emailVerified || user.isDeactivated) {
      return next(new Error("Account not authorized"));
    }

    socket.data.userId = String(user._id);
    socket.data.user = user;

    next();
  } catch (error) {
    console.error("Socket authentication failed:", error.message);
    next(new Error("Your session has expired. Please log in again."));
  }
});

// Send presence updates while respecting privacy settings
function broadcastPresence(user, online, lastSeen = null) {
  const update = {
    userId: String(user._id)
  };

  if (user.showOnlineStatus !== false) {
    update.online = online;
  }

  if (user.showLastSeen !== false && lastSeen) {
    update.lastSeen = lastSeen;
  }

  // Do not broadcast anything if both settings are hidden
  if (
    user.showOnlineStatus === false &&
    user.showLastSeen === false
  ) {
    return;
  }

  io.emit("presence:update", update);
}

io.on("connection", async socket => {
  const userId = socket.data.userId;
  const user = socket.data.user;
  socket.join(`user:${userId}`);

  let connections = activeUsers.get(userId);

  if (!connections) {
    connections = new Set();
    activeUsers.set(userId, connections);
  }

  connections.add(socket.id);

  try {
    await User.updateOne(
      { _id: userId },
      { $set: { online: true } }
    );
  } catch (error) {
    console.error("Could not update online status:", error.message);
  }

  // Tell connected clients that this user is online
  broadcastPresence(user, true);

  // Confirm successful socket authentication to this client
  socket.emit("socket:ready", {
    connected: true,
    userId
  });

  console.log(`Socket connected: ${userId}`);

  socket.on("disconnect", async () => {
    const currentConnections = activeUsers.get(userId);

    if (currentConnections) {
      currentConnections.delete(socket.id);

      // Only mark offline when the user's last connection closes
      if (currentConnections.size === 0) {
        activeUsers.delete(userId);

        const lastSeen = new Date();

        try {
          await User.updateOne(
            { _id: userId },
            {
              $set: {
                online: false,
                lastSeen
              }
            }
          );

          broadcastPresence(user, false, lastSeen);
        } catch (error) {
          console.error("Could not update last seen:", error.message);
        }
      }
    }

    console.log(`Socket disconnected: ${userId}`);
  });
});

// Start server only after MongoDB connects
const port = process.env.PORT || 5000;

if (!process.env.MONGODB_URI || !process.env.JWT_SECRET) {
  console.error(
    "Missing MONGODB_URI or JWT_SECRET. Check your environment variables."
  );
  process.exit(1);
}

mongoose.connect(process.env.MONGODB_URI)
  .then(() => {
    console.log("MongoDB connected");

    httpServer.listen(port, "0.0.0.0", () => {
      console.log(`Bara Cee API listening on ${port}`);
      console.log("Socket.IO is ready");
    });
  })
  .catch(error => {
    console.error("MongoDB connection failed:", error.message);
    process.exit(1);
  });