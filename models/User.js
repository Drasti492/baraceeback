const mongoose = require("mongoose");

const userSchema = new mongoose.Schema({
  username: { type: String, required: true, unique: true, trim: true, lowercase: true, minlength: 3, maxlength: 20, match: /^[a-z0-9_.]+$/ },
  displayName: { type: String, trim: true, maxlength: 40 },
  email: { type: String, required: true, unique: true, lowercase: true, trim: true },
  passwordHash: { type: String, required: true, select: false },
  type: { type: String, enum: ["student", "business", "community"], required: true },

  bizName: { type: String, trim: true, maxlength: 100 },
  bizLocation: { type: String, trim: true, maxlength: 200 },
  bizPermit: { type: String, trim: true, maxlength: 100 },

  // Set verified:true in MongoDB Atlas to give anyone the badge.
  verified: { type: Boolean, default: false },
  emailVerified: { type: Boolean, default: false },

  otpHash: { type: String, select: false },
  otpExpiresAt: { type: Date, select: false },
  otpAttempts: { type: Number, default: 0, select: false },

  avatar: String,

  // Bio
  bio: { type: String, trim: true, maxlength: 160 },
  stay: { type: String, trim: true, maxlength: 60 },       // place of stay around Bara Cee
  location: { type: String, trim: true, maxlength: 60 },   // legacy
  website: { type: String, trim: true, maxlength: 100 },
  course: { type: String, trim: true, maxlength: 60 },
  yearOfStudy: { type: String, enum: ["", "1st year", "2nd year", "3rd year", "4th year", "Super senior", "Alumni"], default: "" },
  age: { type: Number, min: 13, max: 100 },
  hobbies: { type: String, trim: true, maxlength: 100 },

  online: { type: Boolean, default: false },
  lastSeen: Date,

  // Privacy
  showOnlineStatus: { type: Boolean, default: true },
  showLastSeen: { type: Boolean, default: true },
  showAge: { type: Boolean, default: false },
  showEducation: { type: Boolean, default: true },
  lockPosts: { type: Boolean, default: false },

  theme: { type: String, enum: ["light", "dark", "system"], default: "system" },
  isDeactivated: { type: Boolean, default: false },
  deactivatedAt: { type: Date, default: null }
}, { timestamps: true });

module.exports = mongoose.model("User", userSchema);