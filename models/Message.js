const mongoose = require("mongoose");
const schema = new mongoose.Schema({
  from: { type: mongoose.Schema.Types.ObjectId, ref: "User", required: true },
  to: { type: mongoose.Schema.Types.ObjectId, ref: "User", required: true },
  text: { type: String, required: true, maxlength: 2000, trim: true },
  readAt: Date
}, { timestamps: true });
schema.index({ from: 1, to: 1, createdAt: -1 });
module.exports = mongoose.model("Message", schema);
