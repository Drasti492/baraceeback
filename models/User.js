
const mongoose = require("mongoose");

const userSchema = new mongoose.Schema({
  // Unique social-media username
  username: {
    type: String,
    required: true,
    unique: true,
    trim: true,
    lowercase: true,
    minlength: 3,
    maxlength: 20,
    match: /^[a-z0-9_.]+$/
  },

  // Public name displayed above @username
  displayName: {
    type: String,
    trim: true,
    maxlength: 40
  },

  email: {
    type: String,
    required: true,
    unique: true,
    lowercase: true,
    trim: true
  },

  passwordHash: {
    type: String,
    required: true,
    select: false
  },

  type: {
    type: String,
    enum: ["student", "business", "community"],
    required: true
  },

  bizName: { type: String, trim: true, maxlength: 100 },
  bizLocation: { type: String, trim: true, maxlength: 200 },
  bizPermit: { type: String, trim: true, maxlength: 100 },

  verified: { type: Boolean, default: false },
  emailVerified: { type: Boolean, default: false },

  otpHash: { type: String, select: false },
  otpExpiresAt: { type: Date, select: false },
  otpAttempts: { type: Number, default: 0, select: false },

  avatar: String,

  // Live presence
  online: { type: Boolean, default: false },
  lastSeen: Date,

  // Privacy settings
  showOnlineStatus: { type: Boolean, default: true },
  showLastSeen: { type: Boolean, default: true },

  // Account settings
  theme: {
    type: String,
    enum: ["light", "dark", "system"],
    default: "system"
  },

  isDeactivated: { type: Boolean, default: false },
  deactivatedAt: { type: Date, default: null }

}, { timestamps: true });

module.exports = mongoose.model("User", userSchema);
