const mongoose = require("mongoose");
const notificationSchema = new mongoose.Schema({
  recipient: { type: mongoose.Schema.Types.ObjectId, ref: "User", required: true },
  actor: { type: mongoose.Schema.Types.ObjectId, ref: "User" },
  type: { type: String, enum: ["like", "comment", "message", "story_reply", "follow", "system"], required: true },
  body: { type: String, required: true, maxlength: 300 },
  post: { type: mongoose.Schema.Types.ObjectId, ref: "Post" },
  messageRef: { type: mongoose.Schema.Types.ObjectId, ref: "Message" },
  story: { type: mongoose.Schema.Types.ObjectId, ref: "Story" },
  readAt: { type: Date, default: null }
}, { timestamps: true });
notificationSchema.index({ recipient: 1, createdAt: -1 });
notificationSchema.index({ recipient: 1, readAt: 1 });
module.exports = mongoose.model("Notification", notificationSchema);