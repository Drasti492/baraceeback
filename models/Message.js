const mongoose = require("mongoose");
const schema = new mongoose.Schema({
  from: { type: mongoose.Schema.Types.ObjectId, ref: "User", required: true },
  to: { type: mongoose.Schema.Types.ObjectId, ref: "User", required: true },
  text: { type: String, required: true, maxlength: 2000, trim: true },
  readAt: Date,
  deletedAt: Date,
  replyTo: { type: mongoose.Schema.Types.ObjectId, ref: "Message" },
  hearts: [{ type: mongoose.Schema.Types.ObjectId, ref: "User" }],
  // Snapshot of the story so the thumbnail survives after the story expires
  storyReply: {
    story: { type: mongoose.Schema.Types.ObjectId, ref: "Story" },
    media: String,
    text: String,
    expiresAt: Date
  }
}, { timestamps: true });
schema.index({ from: 1, to: 1, createdAt: -1 });
module.exports = mongoose.model("Message", schema);