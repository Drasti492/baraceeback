const mongoose = require("mongoose");
const visibleHours = Number(process.env.LISTING_VISIBLE_HOURS || 30);
const retentionDays = Number(process.env.LISTING_RETENTION_DAYS || 3);
const schema = new mongoose.Schema({
  user: { type: mongoose.Schema.Types.ObjectId, ref: "User", required: true },
  title: { type: String, required: true, trim: true, maxlength: 80 },
  price: { type: Number, required: true, min: 0 },
  image: String,
  expiresAt: { type: Date, default: () => new Date(Date.now() + visibleHours*3600000), index: true },
  deleteAt: { type: Date, default: () => new Date(Date.now() + (visibleHours + retentionDays*24)*3600000), index: { expires: 0 } }
}, { timestamps: true });
module.exports = mongoose.model("Listing", schema);
