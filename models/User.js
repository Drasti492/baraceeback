const mongoose = require("mongoose");
const userSchema = new mongoose.Schema({
  username: { type: String, required: true, unique: true, trim: true, lowercase: true, minlength: 3, maxlength: 20, match: /^[a-z0-9_.]+$/ },
  email: { type: String, required: true, unique: true, lowercase: true, trim: true },
  passwordHash: { type: String, required: true, select: false },
  type: { type: String, enum: ["student", "business", "community"], required: true },
  bizName: { type: String, trim: true, maxlength: 100 },
  bizLocation: { type: String, trim: true, maxlength: 200 },
  bizPermit: { type: String, trim: true, maxlength: 100 },
  verified: { type: Boolean, default: false },
  emailVerified: { type: Boolean, default: false },
  otpHash: { type: String, select: false },
  otpExpiresAt: { type: Date, select: false },
  otpAttempts: { type: Number, default: 0, select: false },
  avatar: String,
  online: { type: Boolean, default: false },
  lastSeen: Date
}, { timestamps: true });
userSchema.index({ email: 1 }, { unique: true });
userSchema.index({ username: 1 }, { unique: true });
module.exports = mongoose.model("User", userSchema);
