const mongoose = require("mongoose");
const { Schema } = mongoose;
const ref = n => ({ type: Schema.Types.ObjectId, ref: n });

const Comment = mongoose.model("Comment", new Schema({
  post: { ...ref("Post"), required: true, index: true },
  user: { ...ref("User"), required: true },
  parent: { ...ref("Comment"), default: null, index: true },
  replyToUser: ref("User"),
  text: { type: String, required: true, maxlength: 500, trim: true },
  likes: [ref("User")]
}, { timestamps: true }));

const dSchema = new Schema({ follower: { ...ref("User"), required: true }, following: { ...ref("User"), required: true } }, { timestamps: true });
dSchema.index({ follower: 1, following: 1 }, { unique: true });
const Disciple = mongoose.model("Disciple", dSchema);

const rSchema = new Schema({ rater: { ...ref("User"), required: true }, target: { ...ref("User"), required: true, index: true }, stars: { type: Number, min: 1, max: 5, required: true } }, { timestamps: true });
rSchema.index({ rater: 1, target: 1 }, { unique: true });
const Rating = mongoose.model("Rating", rSchema);

const bSchema = new Schema({ blocker: { ...ref("User"), required: true }, blocked: { ...ref("User"), required: true } }, { timestamps: true });
bSchema.index({ blocker: 1, blocked: 1 }, { unique: true });
const Block = mongoose.model("Block", bSchema);

const OtpThrottle = mongoose.model("OtpThrottle", new Schema({
  key: { type: String, unique: true },
  times: [Date],
  expiresAt: { type: Date, index: { expires: 0 } }
}));

const PendingSignup = mongoose.model("PendingSignup", new Schema({
  email: { type: String, unique: true, lowercase: true },
  username: String, passwordHash: String, type: String,
  bizName: String, bizLocation: String, bizPermit: String,
  otpHash: String, otpExpiresAt: Date, otpAttempts: { type: Number, default: 0 },
  expiresAt: { type: Date, index: { expires: 0 } }
}));

module.exports = { Comment, Disciple, Rating, Block, OtpThrottle, PendingSignup };