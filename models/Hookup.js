const mongoose = require("mongoose");
const { Schema } = mongoose;
const ref = n => ({ type: Schema.Types.ObjectId, ref: n });

const HookupProfile = mongoose.model("HookupProfile", new Schema({
  user: { ...ref("User"), required: true, unique: true },
  alias: { type: String, required: true, unique: true },          // public ID, e.g. HK-7F2A9C
  gender: { type: String, enum: ["male", "female"], required: true },
  birthDate: { type: Date, required: true, select: false },        // private, used only for the 18+ check and age
  status: { type: String, enum: ["single", "complicated"], default: "single" },
  lookingFor: [{ type: String, enum: ["relationship", "dating", "friendship", "casual", "buddy"] }],
  interestedIn: { type: String, enum: ["men", "women", "everyone"], default: "everyone" },
  bio: { type: String, maxlength: 200, default: "" },
  interests: { type: String, maxlength: 100, default: "" },
  area: { type: String, maxlength: 60, default: "" },
  active: { type: Boolean, default: true },                        // visible in People / Feed
  showUsername: { type: Boolean, default: false },                 // show real username to everyone
  flagged: { type: Boolean, default: false },                      // hidden pending admin review
  agreedAt: Date
}, { timestamps: true }));

const HookupPost = mongoose.model("HookupPost", new Schema({
  author: { ...ref("HookupProfile"), required: true, index: true },
  text: { type: String, required: true, maxlength: 300, trim: true },
  audience: { type: String, enum: ["all", "selected"], default: "all" },
  allowed: [ref("HookupProfile")],
  likes: [ref("HookupProfile")]
}, { timestamps: true }));

const HookupMessage = mongoose.model("HookupMessage", new Schema({
  from: { ...ref("HookupProfile"), required: true },
  to: { ...ref("HookupProfile"), required: true },
  text: { type: String, required: true, maxlength: 1000, trim: true },
  kind: { type: String, enum: ["text", "reveal", "hide"], default: "text" },
  readAt: Date
}, { timestamps: true }));
HookupMessage.schema.index({ from: 1, to: 1, createdAt: -1 });

const rv = new Schema({ from: { ...ref("HookupProfile"), required: true }, to: { ...ref("HookupProfile"), required: true } }, { timestamps: true });
rv.index({ from: 1, to: 1 }, { unique: true });
const HookupReveal = mongoose.model("HookupReveal", rv);

const bl = new Schema({ blocker: { ...ref("HookupProfile"), required: true }, blocked: { ...ref("HookupProfile"), required: true } }, { timestamps: true });
bl.index({ blocker: 1, blocked: 1 }, { unique: true });
const HookupBlock = mongoose.model("HookupBlock", bl);

const HookupReport = mongoose.model("HookupReport", new Schema({
  reporter: { ...ref("HookupProfile"), required: true },
  target: { ...ref("HookupProfile"), required: true, index: true },
  reason: { type: String, enum: ["spam", "harassment", "underage", "scam", "other"], required: true },
  text: { type: String, maxlength: 200, default: "" }
}, { timestamps: true }));

module.exports = { HookupProfile, HookupPost, HookupMessage, HookupReveal, HookupBlock, HookupReport };