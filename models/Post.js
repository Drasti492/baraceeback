const mongoose = require("mongoose");
const postSchema = new mongoose.Schema({
  user: { type: mongoose.Schema.Types.ObjectId, ref: "User", required: true },
  text: { type: String, maxlength: 2000, default: "" },
  media: String, // first media url (kept for old posts)
  mediaList: [{ _id: false, url: String, kind: String }],
  editedAt: Date,
  likes: [{ type: mongoose.Schema.Types.ObjectId, ref: "User" }],
  comments: [{ user: { type: mongoose.Schema.Types.ObjectId, ref: "User" }, username: String, text: { type: String, maxlength: 500 }, createdAt: { type: Date, default: Date.now } }] // legacy
}, { timestamps: true });
postSchema.index({ createdAt: -1 });
module.exports = mongoose.model("Post", postSchema);