const mongoose = require("mongoose");
const schema = new mongoose.Schema({
  user: { type: mongoose.Schema.Types.ObjectId, ref: "User", required: true },
  text: { type: String, maxlength: 200, default: "" }, media: String,
  expiresAt: { type: Date, default: () => new Date(Date.now() + 24*60*60*1000), index: { expires: 0 } }
}, { timestamps: true });
module.exports = mongoose.model("Story", schema);
