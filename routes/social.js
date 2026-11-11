// routes/social.js — mounted FIRST (before extras.js and api.js).
const express = require("express");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const multer = require("multer");
const rateLimit = require("express-rate-limit");
const router = express.Router();
const User = require("../models/User");
const Post = require("../models/Post");
const Story = require("../models/Story");
const Listing = require("../models/Listing");
const Message = require("../models/Message");
const Notification = require("../models/Notification");
const { Comment, Disciple, Rating, Block, OtpThrottle, PendingSignup } = require("../models/Social");
const auth = require("../middleware/auth");
const { makeOtp, hashOtp } = require("../utils/otp");
const { saveFile } = require("../utils/storage");
const { clean, rx, isId, S, publicUser, emit, notify, sendCode } = require("../utils/helpers");

const MB = 1048576;
const YEARS = ["", "1st year", "2nd year", "3rd year", "4th year", "Super senior", "Alumni"];
const upload = multer({
  storage: multer.memoryStorage(),
  limits: { fileSize: 25 * MB, files: 6 },
  fileFilter: (_r, f, cb) => {
    const ok = /^(image\/(jpeg|png|webp|gif)|video\/(mp4|webm|quicktime))$/.test(f.mimetype);
    cb(ok ? null : Object.assign(new Error("Only JPG, PNG, WEBP, GIF, MP4 or WEBM files are allowed."), { status: 400, expose: true }), ok);
  }
});
const issueToken = u => jwt.sign({ sub: S(u._id) }, process.env.JWT_SECRET, { expiresIn: process.env.JWT_EXPIRES_IN || "30d" });

/* ---------- shared shapes ---------- */
const meUser = u => ({
  ...publicUser(u), email: u.email, bio: u.bio || "", stay: u.stay || "", website: u.website || "", hobbies: u.hobbies || "",
  course: u.course || "", yearOfStudy: u.yearOfStudy || "", age: u.age || "", bizLocation: u.bizLocation || "",
  theme: u.theme, showOnlineStatus: u.showOnlineStatus !== false, showLastSeen: u.showLastSeen !== false,
  showAge: !!u.showAge, showEducation: u.showEducation !== false, lockPosts: !!u.lockPosts
});
const isBlocked = (a, b) => Block.exists({ $or: [{ blocker: a, blocked: b }, { blocker: b, blocked: a }] });

async function throttle(kind, email) {
  const key = `${kind}:${email}`, now = Date.now(), day = 86400000;
  const t = (await OtpThrottle.findOne({ key })) || new OtpThrottle({ key, times: [] });
  t.times = t.times.filter(d => now - d.getTime() < day);
  if (t.times.length >= 3) return { ok: false, wait: Math.max(1, Math.ceil((t.times[0].getTime() + day - now) / 3600000)) };
  t.times.push(new Date()); t.expiresAt = new Date(now + day + 3600000);
  await t.save();
  return { ok: true };
}
const limitMsg = w => `You can only request 3 codes per day. Please try again in about ${w} hour${w > 1 ? "s" : ""}.`;

/* ================= AUTH (nothing is saved until the email is verified) ================= */
router.post("/auth/signup", async (req, res) => {
  const { username, email, password, type, bizName, bizLocation, bizPermit } = req.body || {};
  const uname = clean(username).toLowerCase(), mail = clean(email).toLowerCase();
  if (!/^[a-z0-9_.]{3,20}$/.test(uname)) return res.status(400).json({ error: "Username must be 3–20 letters, numbers, dots or underscores." });
  if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(mail)) return res.status(400).json({ error: "Enter a valid email address." });
  if (typeof password !== "string" || password.length < 6) return res.status(400).json({ error: "Use a password of at least 6 characters." });
  if (!["student", "business", "community"].includes(type)) return res.status(400).json({ error: "Choose Student, Business or Community." });
  if (type === "business" && (!clean(bizName) || !clean(bizLocation))) return res.status(400).json({ error: "Business name and location are required." });
  if (await User.exists({ emailVerified: true, $or: [{ username: uname }, { email: mail }] })) return res.status(409).json({ error: "That username or email is already registered." });
  await User.deleteMany({ emailVerified: false, $or: [{ username: uname }, { email: mail }] });
  const t = await throttle("verify", mail);
  if (!t.ok) return res.status(429).json({ error: limitMsg(t.wait) });
  const code = makeOtp();
  await PendingSignup.findOneAndUpdate({ email: mail }, { $set: {
    username: uname, passwordHash: await bcrypt.hash(password, 12), type,
    bizName: type === "business" ? clean(bizName) : undefined,
    bizLocation: type === "business" ? clean(bizLocation) : undefined,
    bizPermit: type === "business" ? clean(bizPermit) : undefined,
    otpHash: hashOtp(code), otpExpiresAt: new Date(Date.now() + 600000), otpAttempts: 0,
    expiresAt: new Date(Date.now() + 3600000)
  } }, { upsert: true });
  try { await sendCode(mail, code, "Your Bara Cee verification code", "Use this code to verify your email address:"); }
  catch (e) {
    await PendingSignup.deleteOne({ email: mail });
    console.error("Brevo send failed:", e.response?.data || e.message);
    return res.status(502).json({ error: "We could not send your verification email. Please try again." });
  }
  res.status(201).json({ ok: true, requiresVerification: true, email: mail });
});

router.post("/auth/verify-email", async (req, res) => {
  const email = clean(req.body?.email).toLowerCase(), code = clean(req.body?.code);
  if (!email || !/^\d{6}$/.test(code)) return res.status(400).json({ error: "Enter your email and the 6-digit code." });
  const p = await PendingSignup.findOne({ email });
  if (!p) {
    if (await User.exists({ email, emailVerified: true })) return res.json({ ok: true, message: "Email already verified. Please log in." });
    return res.status(400).json({ error: "Your signup expired. Please sign up again." });
  }
  if (p.otpAttempts >= 5) return res.status(429).json({ error: "Too many attempts. Request a new code." });
  if (!p.otpExpiresAt || p.otpExpiresAt < new Date()) return res.status(400).json({ error: "Code expired. Request a new one." });
  p.otpAttempts += 1;
  if (p.otpHash !== hashOtp(code)) { await p.save(); return res.status(400).json({ error: "Incorrect verification code." }); }
  try {
    await User.create({ username: p.username, email: p.email, passwordHash: p.passwordHash, type: p.type, bizName: p.bizName, bizLocation: p.bizLocation, bizPermit: p.bizPermit, emailVerified: true });
  } catch (e) {
    if (e.code === 11000) { await PendingSignup.deleteOne({ _id: p._id }); return res.status(409).json({ error: "That username or email was just taken. Please sign up again." }); }
    throw e;
  }
  await PendingSignup.deleteOne({ _id: p._id });
  res.json({ ok: true, message: "Email verified. You can now log in." });
});

router.post("/auth/resend-code", async (req, res) => {
  const email = clean(req.body?.email).toLowerCase();
  const p = await PendingSignup.findOne({ email });
  if (!p) return res.status(400).json({ error: "Your signup expired. Please sign up again." });
  const t = await throttle("verify", email);
  if (!t.ok) return res.status(429).json({ error: limitMsg(t.wait) });
  const code = makeOtp();
  p.otpHash = hashOtp(code); p.otpExpiresAt = new Date(Date.now() + 600000); p.otpAttempts = 0; p.expiresAt = new Date(Date.now() + 3600000);
  await p.save();
  try { await sendCode(email, code, "Your Bara Cee verification code", "Use this code to verify your email address:"); }
  catch (e) { console.error("Brevo resend failed:", e.response?.data || e.message); return res.status(502).json({ error: "Could not send email. Try again later." }); }
  res.json({ ok: true, message: "A new code has been sent." });
});

router.post("/auth/login", async (req, res) => {
  const id = clean(req.body?.username).toLowerCase(), password = req.body?.password;
  const user = id ? await User.findOne({ emailVerified: true, $or: [{ username: id }, { email: id }] }).select("+passwordHash") : null;
  if (!user || !(await bcrypt.compare(String(password || ""), user.passwordHash))) return res.status(401).json({ error: "Incorrect username/email or password." });
  user.online = true; user.lastSeen = new Date(); await user.save();
  res.json({ token: issueToken(user), user: publicUser(user) });
});

router.post("/auth/forgot-password", async (req, res) => {
  const email = clean(req.body?.email).toLowerCase();
  const generic = { ok: true, message: "If that email is registered, a reset code has been sent." };
  if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) return res.status(400).json({ error: "Enter a valid email address." });
  const t = await throttle("reset", email);
  if (!t.ok) return res.status(429).json({ error: limitMsg(t.wait) });
  const u = await User.findOne({ email, emailVerified: true }).select("+otpHash +otpExpiresAt +otpAttempts");
  if (!u) return res.json(generic);
  const code = makeOtp();
  u.otpHash = hashOtp(code); u.otpExpiresAt = new Date(Date.now() + 600000); u.otpAttempts = 0; await u.save();
  try { await sendCode(email, code, "Your Bara Cee password reset code", "Use this code to reset your password:"); }
  catch (e) { console.error("Reset email failed:", e.response?.data || e.message); return res.status(502).json({ error: "Could not send email. Try again later." }); }
  res.json(generic);
});

router.post("/auth/reset-password", async (req, res) => {
  const email = clean(req.body?.email).toLowerCase(), code = clean(req.body?.code), password = req.body?.password;
  if (!/^\d{6}$/.test(code)) return res.status(400).json({ error: "Enter the 6-digit code." });
  if (typeof password !== "string" || password.length < 6) return res.status(400).json({ error: "Use a password of at least 6 characters." });
  const u = await User.findOne({ email, emailVerified: true }).select("+passwordHash +otpHash +otpExpiresAt +otpAttempts");
  if (!u || !u.otpHash) return res.status(400).json({ error: "Invalid or expired code." });
  if (u.otpAttempts >= 5) return res.status(429).json({ error: "Too many attempts. Request a new code." });
  if (!u.otpExpiresAt || u.otpExpiresAt < new Date()) return res.status(400).json({ error: "Code expired. Request a new one." });
  u.otpAttempts += 1;
  if (u.otpHash !== hashOtp(code)) { await u.save(); return res.status(400).json({ error: "Incorrect code." }); }
  u.passwordHash = await bcrypt.hash(password, 12); u.otpHash = undefined; u.otpExpiresAt = undefined; u.otpAttempts = 0;
  await u.save();
  res.json({ ok: true, message: "Password updated. You can log in now." });
});

router.post("/auth/change-password", auth, async (req, res) => {
  const { current, password } = req.body || {};
  if (typeof password !== "string" || password.length < 6) return res.status(400).json({ error: "Use a new password of at least 6 characters." });
  const u = await User.findById(req.user._id).select("+passwordHash");
  if (!(await bcrypt.compare(String(current || ""), u.passwordHash))) return res.status(401).json({ error: "Your current password is incorrect." });
  u.passwordHash = await bcrypt.hash(password, 12); await u.save();
  res.json({ ok: true });
});

router.get("/users/check-username",
  rateLimit({ windowMs: 60000, limit: 60, standardHeaders: true, legacyHeaders: false }),
  async (req, res) => {
    const u = clean(req.query.u).toLowerCase();
    if (!/^[a-z0-9_.]{3,20}$/.test(u)) return res.json({ available: false, reason: "Use 3–20 letters, numbers, dots or underscores." });
    const taken = await User.exists({ username: u, emailVerified: true });
    res.json({ available: !taken, reason: taken ? "That username is already taken." : "" });
  });

/* ================= ME / PROFILE / SETTINGS ================= */
router.get("/me", auth, (req, res) => res.json(meUser(req.user)));

router.patch("/profile", auth, async (req, res) => {
  const b = req.body || {}, u = req.user;
  if (b.username !== undefined) {
    const uname = clean(b.username).toLowerCase();
    if (uname !== u.username) {
      if (!/^[a-z0-9_.]{3,20}$/.test(uname)) return res.status(400).json({ error: "Username must be 3–20 letters, numbers, dots or underscores." });
      if (await User.exists({ username: uname })) return res.status(409).json({ error: "That username is already taken." });
      u.username = uname;
    }
  }
  const txt = (k, n) => { if (b[k] !== undefined) u[k] = clean(b[k]).slice(0, n); };
  txt("displayName", 40); txt("bio", 160); txt("stay", 60); txt("course", 60); txt("hobbies", 100);
  if (b.website !== undefined) {
    let w = clean(b.website).slice(0, 100);
    if (w && !/^https?:\/\//i.test(w)) w = "https://" + w;
    u.website = w;
  }
  if (b.yearOfStudy !== undefined) {
    if (!YEARS.includes(b.yearOfStudy)) return res.status(400).json({ error: "Choose a valid year of study." });
    u.yearOfStudy = b.yearOfStudy;
  }
  if (b.age !== undefined) {
    if (b.age === "" || b.age === null) u.age = undefined;
    else { const n = Number(b.age); if (!Number.isInteger(n) || n < 13 || n > 100) return res.status(400).json({ error: "Age must be between 13 and 100." }); u.age = n; }
  }
  try { await u.save(); } catch (e) {
    if (e.code === 11000) return res.status(409).json({ error: "That username is already taken." });
    throw e;
  }
  res.json(meUser(u));
});

router.patch("/settings", auth, async (req, res) => {
  const b = req.body || {}, u = req.user;
  for (const k of ["showOnlineStatus", "showLastSeen", "showAge", "showEducation", "lockPosts"]) if (typeof b[k] === "boolean") u[k] = b[k];
  if (["light", "dark", "system"].includes(b.theme)) u.theme = b.theme;
  await u.save();
  res.json(meUser(u));
});

router.post("/avatar", auth, upload.single("f"), async (req, res) => {
  if (!req.file || !req.file.mimetype.startsWith("image/")) return res.status(400).json({ error: "Choose an image." });
  if (req.file.size > 10 * MB) return res.status(400).json({ error: "Photo is too large (10MB max)." });
  req.user.avatar = await saveFile(req.file); await req.user.save();
  res.json({ avatar: req.user.avatar });
});

/* ================= PROFILE PAGE / DISCIPLES / RATINGS / BLOCKS ================= */
router.get("/users/:id/profile", auth, async (req, res) => {
  if (!isId(req.params.id)) return res.status(404).json({ error: "User not found." });
  const u = await User.findOne({ _id: req.params.id, emailVerified: true });
  if (!u) return res.status(404).json({ error: "User not found." });
  const me = req.user._id, isMe = S(u._id) === S(me);
  const [disciples, discipling, posts, agg, mine, iDisciple, iBlocked, blockedMe] = await Promise.all([
    Disciple.countDocuments({ following: u._id }), Disciple.countDocuments({ follower: u._id }),
    Post.countDocuments({ user: u._id }),
    Rating.aggregate([{ $match: { target: u._id } }, { $group: { _id: null, avg: { $avg: "$stars" }, n: { $sum: 1 } } }]),
    Rating.findOne({ rater: me, target: u._id }), Disciple.exists({ follower: me, following: u._id }),
    Block.exists({ blocker: me, blocked: u._id }), Block.exists({ blocker: u._id, blocked: me })
  ]);
  const edu = isMe || u.showEducation !== false;
  res.json({
    isMe, iDisciple: !!iDisciple, iBlocked: !!iBlocked, blockedMe: !!blockedMe,
    locked: !isMe && !!u.lockPosts,
    user: {
      ...publicUser(u), bio: u.bio || "", stay: u.stay || "", website: u.website || "", hobbies: u.hobbies || "",
      course: edu ? u.course || "" : "", yearOfStudy: edu ? u.yearOfStudy || "" : "",
      age: isMe || u.showAge ? u.age || null : null, bizLocation: u.type === "business" ? u.bizLocation || "" : "",
      joinedAt: u.createdAt, lastSeen: isMe || u.showLastSeen !== false ? u.lastSeen || null : null
    },
    stats: { disciples, discipling, posts, rating: { avg: agg[0] ? Math.round(agg[0].avg * 10) / 10 : 0, n: agg[0]?.n || 0, mine: mine?.stars || 0 } }
  });
});

router.post("/users/:id/disciple", auth, async (req, res) => {
  if (!isId(req.params.id) || S(req.user._id) === req.params.id) return res.status(400).json({ error: "Invalid request." });
  const t = await User.findOne({ _id: req.params.id, emailVerified: true });
  if (!t) return res.status(404).json({ error: "User not found." });
  const q = { follower: req.user._id, following: t._id };
  if (await Disciple.exists(q)) await Disciple.deleteOne(q);
  else {
    if (await isBlocked(req.user._id, t._id)) return res.status(403).json({ error: "You can't do that with this account." });
    await Disciple.create(q);
    await notify(req, { recipient: t._id, actor: req.user._id, type: "follow", body: `${req.user.username} is now your disciple.` });
  }
  res.json({ iDisciple: !!(await Disciple.exists(q)), disciples: await Disciple.countDocuments({ following: t._id }) });
});

router.post("/users/:id/rate", auth, async (req, res) => {
  const stars = Number(req.body?.stars);
  if (!isId(req.params.id) || S(req.user._id) === req.params.id) return res.status(400).json({ error: "You can't rate yourself." });
  if (!Number.isInteger(stars) || stars < 0 || stars > 5) return res.status(400).json({ error: "Choose 1 to 5 stars." });
  const t = await User.findOne({ _id: req.params.id, emailVerified: true });
  if (!t) return res.status(404).json({ error: "User not found." });
  if (await isBlocked(req.user._id, t._id)) return res.status(403).json({ error: "You can't rate this account." });
  if (stars === 0) await Rating.deleteOne({ rater: req.user._id, target: t._id });
  else await Rating.updateOne({ rater: req.user._id, target: t._id }, { $set: { stars } }, { upsert: true });
  const agg = await Rating.aggregate([{ $match: { target: t._id } }, { $group: { _id: null, avg: { $avg: "$stars" }, n: { $sum: 1 } } }]);
  res.json({ avg: agg[0] ? Math.round(agg[0].avg * 10) / 10 : 0, n: agg[0]?.n || 0, mine: stars });
});

router.post("/users/:id/block", auth, async (req, res) => {
  if (!isId(req.params.id) || S(req.user._id) === req.params.id) return res.status(400).json({ error: "Invalid request." });
  await Block.updateOne({ blocker: req.user._id, blocked: req.params.id }, {}, { upsert: true });
  await Disciple.deleteMany({ $or: [{ follower: req.user._id, following: req.params.id }, { follower: req.params.id, following: req.user._id }] });
  res.json({ ok: true });
});
router.delete("/users/:id/block", auth, async (req, res) => {
  if (!isId(req.params.id)) return res.status(400).json({ error: "Invalid request." });
  await Block.deleteOne({ blocker: req.user._id, blocked: req.params.id });
  res.json({ ok: true });
});
router.get("/blocks", auth, async (req, res) => {
  const ids = await Block.find({ blocker: req.user._id }).distinct("blocked");
  res.json((await User.find({ _id: { $in: ids } })).map(publicUser));
});

router.get("/chat/:userId/info", auth, async (req, res) => {
  if (!isId(req.params.userId)) return res.status(404).json({ error: "User not found." });
  const u = await User.findOne({ _id: req.params.userId, emailVerified: true });
  if (!u) return res.status(404).json({ error: "User not found." });
  const [iBlocked, blockedMe] = await Promise.all([Block.exists({ blocker: req.user._id, blocked: u._id }), Block.exists({ blocker: u._id, blocked: req.user._id })]);
  res.json({ user: publicUser(u), online: !!u.online && u.showOnlineStatus !== false, lastSeen: u.showLastSeen !== false ? u.lastSeen || null : null, iBlocked: !!iBlocked, blockedMe: !!blockedMe });
});

/* ================= POSTS ================= */
const mediaOf = p => (p.mediaList && p.mediaList.length ? p.mediaList.map(m => ({ url: m.url, kind: m.kind })) : p.media ? [{ url: p.media, kind: /\.(mp4|webm|mov)$/i.test(p.media) ? "video" : "image" }] : []);
const shapePost = (p, meId, counts) => ({
  id: S(p._id), text: p.text, media: mediaOf(p), createdAt: p.createdAt, editedAt: p.editedAt || null,
  canEdit: S(p.user._id) === S(meId) && Date.now() - new Date(p.createdAt).getTime() < 3 * 3600000,
  likes: p.likes.length, likedByMe: p.likes.some(x => S(x) === S(meId)),
  commentCount: counts.get(S(p._id)) || 0, user: publicUser(p.user)
});
async function listPosts(filter, meId, { sort = "new", limit = 60 } = {}) {
  let posts = await Post.find(filter).populate("user").sort(sort === "oldest" ? { createdAt: 1 } : { createdAt: -1 }).limit(sort === "popular" ? 150 : limit);
  if (sort === "popular") posts = posts.sort((a, b) => b.likes.length - a.likes.length).slice(0, limit);
  posts = posts.filter(p => p.user);
  const counts = new Map((await Comment.aggregate([{ $match: { post: { $in: posts.map(p => p._id) } } }, { $group: { _id: "$post", n: { $sum: 1 } } }])).map(r => [S(r._id), r.n]));
  return posts.map(p => shapePost(p, meId, counts));
}
const hiddenUsers = async me => {
  const [blocked, locked] = await Promise.all([Block.find({ blocker: me._id }).distinct("blocked"), User.find({ lockPosts: true, _id: { $ne: me._id } }).distinct("_id")]);
  return [...blocked, ...locked];
};

router.get("/posts", auth, async (req, res) => {
  const filter = { user: { $nin: await hiddenUsers(req.user) } };
  if (["student", "business", "community"].includes(req.query.type)) filter.user.$in = await User.find({ type: req.query.type }).distinct("_id");
  if (req.query.tag) filter.text = { $regex: `#${rx(req.query.tag)}`, $options: "i" };
  res.json(await listPosts(filter, req.user._id, { sort: req.query.sort }));
});

router.get("/posts/:id", auth, async (req, res) => {
  if (!isId(req.params.id)) return res.status(404).json({ error: "Post not found." });
  const p = await Post.findById(req.params.id).populate("user");
  if (!p || !p.user) return res.status(404).json({ error: "Post not found." });
  if (S(p.user._id) !== S(req.user._id) && p.user.lockPosts) return res.status(404).json({ error: "This post is locked." });
  const counts = new Map([[S(p._id), await Comment.countDocuments({ post: p._id })]]);
  res.json(shapePost(p, req.user._id, counts));
});

router.get("/users/:id/posts", auth, async (req, res) => {
  if (!isId(req.params.id)) return res.status(404).json({ error: "User not found." });
  const u = await User.findOne({ _id: req.params.id, emailVerified: true });
  if (!u) return res.status(404).json({ error: "User not found." });
  if (S(u._id) !== S(req.user._id) && u.lockPosts) return res.json({ locked: true, posts: [] });
  res.json({ locked: false, posts: await listPosts({ user: u._id }, req.user._id) });
});

router.post("/posts", auth, upload.array("files", 3), async (req, res) => {
  const text = clean(req.body.text), files = req.files || [];
  if (text.length > 500) return res.status(400).json({ error: "Posts are limited to 500 characters." });
  const vids = files.filter(f => f.mimetype.startsWith("video")), imgs = files.filter(f => f.mimetype.startsWith("image"));
  if (vids.length && imgs.length) return res.status(400).json({ error: "Post either photos or one video, not both." });
  if (vids.length > 1) return res.status(400).json({ error: "Only one video per post." });
  if (imgs.some(f => f.size > 10 * MB)) return res.status(400).json({ error: "Each photo must be 10MB or smaller." });
  if (vids.some(f => f.size > 25 * MB)) return res.status(400).json({ error: "Video is too large (25MB max)." });
  if (!text && !files.length) return res.status(400).json({ error: "Write something or attach media." });
  const mediaList = [];
  for (const f of files) mediaList.push({ url: await saveFile(f), kind: f.mimetype.startsWith("video") ? "video" : "image" });
  const post = await Post.create({ user: req.user._id, text, media: mediaList[0]?.url, mediaList });
  res.status(201).json({ id: S(post._id) });
});

router.patch("/posts/:id", auth, async (req, res) => {
  if (!isId(req.params.id)) return res.status(404).json({ error: "Post not found." });
  const p = await Post.findOne({ _id: req.params.id, user: req.user._id });
  if (!p) return res.status(404).json({ error: "Post not found." });
  if (Date.now() - p.createdAt.getTime() > 3 * 3600000) return res.status(403).json({ error: "Posts can only be edited within 3 hours of posting." });
  const text = clean(req.body?.text);
  if (text.length > 500) return res.status(400).json({ error: "Posts are limited to 500 characters." });
  if (!text && !mediaOf(p).length) return res.status(400).json({ error: "A post can't be empty." });
  p.text = text; p.editedAt = new Date(); await p.save();
  res.json({ ok: true });
});

router.delete("/posts/:id", auth, async (req, res) => {
  if (!isId(req.params.id)) return res.status(404).json({ error: "Post not found." });
  const p = await Post.findOneAndDelete({ _id: req.params.id, user: req.user._id });
  if (!p) return res.status(404).json({ error: "Post not found." });
  await Promise.all([Comment.deleteMany({ post: p._id }), Notification.deleteMany({ post: p._id })]);
  res.json({ ok: true });
});

/* ================= COMMENTS (with replies and likes) ================= */
const shapeComment = (c, meId, replyCount = 0) => ({
  id: S(c._id), text: c.text, createdAt: c.createdAt, likes: c.likes.length, likedByMe: c.likes.some(x => S(x) === S(meId)),
  replyCount, parent: c.parent ? S(c.parent) : null,
  replyTo: c.replyToUser && c.replyToUser.username ? { id: S(c.replyToUser._id), username: c.replyToUser.username } : null,
  user: publicUser(c.user)
});

router.get("/posts/:id/comments", auth, async (req, res) => {
  if (!isId(req.params.id)) return res.status(404).json({ error: "Post not found." });
  const skip = Math.max(0, Number(req.query.skip) || 0), limit = Math.min(30, Math.max(1, Number(req.query.limit) || 20));
  const q = { post: req.params.id, parent: null };
  const [rows, total] = await Promise.all([Comment.find(q).populate("user").populate("replyToUser", "username").sort({ createdAt: -1 }).skip(skip).limit(limit), Comment.countDocuments(q)]);
  const live = rows.filter(c => c.user);
  const counts = new Map((await Comment.aggregate([{ $match: { parent: { $in: live.map(c => c._id) } } }, { $group: { _id: "$parent", n: { $sum: 1 } } }])).map(r => [S(r._id), r.n]));
  res.json({ total, comments: live.map(c => shapeComment(c, req.user._id, counts.get(S(c._id)) || 0)) });
});

router.get("/comments/:id/replies", auth, async (req, res) => {
  if (!isId(req.params.id)) return res.status(404).json({ error: "Comment not found." });
  const rows = await Comment.find({ parent: req.params.id }).populate("user").populate("replyToUser", "username").sort({ createdAt: 1 }).limit(100);
  res.json(rows.filter(c => c.user).map(c => shapeComment(c, req.user._id)));
});

router.post("/posts/:id/comments", auth, async (req, res) => {
  if (!isId(req.params.id)) return res.status(404).json({ error: "Post not found." });
  const text = clean(req.body?.text);
  if (!text || text.length > 500) return res.status(400).json({ error: "Comment must be 1–500 characters." });
  const post = await Post.findById(req.params.id);
  if (!post) return res.status(404).json({ error: "Post not found." });
  if (await Block.exists({ blocker: post.user, blocked: req.user._id })) return res.status(403).json({ error: "You can't comment on this person's posts." });
  let parent = null, replyToUser;
  if (req.body?.replyToComment) {
    const target = isId(req.body.replyToComment) ? await Comment.findOne({ _id: req.body.replyToComment, post: post._id }) : null;
    if (!target) return res.status(404).json({ error: "The comment you replied to no longer exists." });
    parent = target.parent || target._id; replyToUser = target.user;
  }
  const c = await Comment.create({ post: post._id, user: req.user._id, parent, replyToUser, text });
  await c.populate([{ path: "user" }, { path: "replyToUser", select: "username" }]);
  if (replyToUser) await notify(req, { recipient: replyToUser, actor: req.user._id, type: "comment", body: `${req.user.username} replied: ${text.slice(0, 100)}`, post: post._id });
  if (!replyToUser || S(replyToUser) !== S(post.user)) await notify(req, { recipient: post.user, actor: req.user._id, type: "comment", body: `${req.user.username} commented: ${text.slice(0, 100)}`, post: post._id });
  res.status(201).json(shapeComment(c, req.user._id));
});

router.post("/comments/:id/like", auth, async (req, res) => {
  if (!isId(req.params.id)) return res.status(404).json({ error: "Comment not found." });
  const c = await Comment.findById(req.params.id);
  if (!c) return res.status(404).json({ error: "Comment not found." });
  const i = c.likes.findIndex(x => S(x) === S(req.user._id));
  if (i < 0) c.likes.push(req.user._id); else c.likes.splice(i, 1);
  await c.save();
  if (i < 0) await notify(req, { recipient: c.user, actor: req.user._id, type: "like", body: `${req.user.username} liked your comment.`, post: c.post });
  res.json({ likes: c.likes.length, likedByMe: i < 0 });
});

router.delete("/comments/:id", auth, async (req, res) => {
  if (!isId(req.params.id)) return res.status(404).json({ error: "Comment not found." });
  const c = await Comment.findById(req.params.id);
  if (!c) return res.status(404).json({ error: "Comment not found." });
  const post = await Post.findById(c.post);
  if (S(c.user) !== S(req.user._id) && !(post && S(post.user) === S(req.user._id))) return res.status(403).json({ error: "You can't delete this comment." });
  await Comment.deleteMany({ $or: [{ _id: c._id }, { parent: c._id }] });
  res.json({ ok: true });
});

/* ================= STORIES / LISTINGS (persistent uploads) ================= */
router.get("/stories", auth, async (req, res) => {
  const blocked = await Block.find({ blocker: req.user._id }).distinct("blocked");
  const rows = await Story.find({ expiresAt: { $gt: new Date() }, user: { $nin: blocked } }).populate("user").sort({ createdAt: 1 }).limit(200);
  res.json(rows.filter(s => s.user).map(s => ({ id: S(s._id), text: s.text, media: s.media, createdAt: s.createdAt, user: publicUser(s.user) })));
});
router.post("/stories", auth, upload.single("f"), async (req, res) => {
  const text = clean(req.body.text).slice(0, 200);
  if (!text && !req.file) return res.status(400).json({ error: "Add text or media." });
  if (req.file && req.file.size > 25 * MB) return res.status(400).json({ error: "File is too large." });
  const s = await Story.create({ user: req.user._id, text, media: req.file ? await saveFile(req.file) : undefined });
  res.status(201).json({ id: S(s._id) });
});

router.post("/listings", auth, upload.array("files", 6), async (req, res) => {
  const title = clean(req.body.title), price = Number(req.body.price), description = clean(req.body.description).slice(0, 300), files = req.files || [];
  if (!title || title.length > 80 || !Number.isFinite(price) || price < 0) return res.status(400).json({ error: "Enter a valid title and price." });
  if (files.some(f => !f.mimetype.startsWith("image/") || f.size > 10 * MB)) return res.status(400).json({ error: "Listings accept photos only, 10MB each." });
  if (await Listing.countDocuments({ user: req.user._id, expiresAt: { $gt: new Date() } }) >= 10) return res.status(403).json({ error: "You have reached the 10 active-listing limit." });
  const images = []; for (const f of files) images.push(await saveFile(f));
  const l = await Listing.create({ user: req.user._id, title, price, description, image: images[0], images });
  res.status(201).json({ id: S(l._id) });
});

/* ================= MESSAGES (photos, view-once, blocks) ================= */
const shapeMsg = (m, refs, meId) => {
  const ref = m.replyTo ? refs.get(S(m.replyTo)) : null;
  const sr = m.storyReply && m.storyReply.story ? m.storyReply : null;
  const once = !!(m.media && m.viewOnce);
  return {
    id: S(m._id), from: S(m.from), text: m.deletedAt ? "" : (m.media && m.text === "Photo" ? "" : m.text), deleted: !!m.deletedAt,
    createdAt: m.createdAt, readAt: m.readAt || null, hearts: m.hearts.length, heartedByMe: m.hearts.some(x => S(x) === S(meId)),
    kind: m.deletedAt ? "text" : once ? "once" : m.media ? "image" : "text",
    media: m.deletedAt || once ? null : m.media || null, opened: !!m.viewedAt,
    replyTo: m.replyTo ? (ref ? { id: S(ref._id), from: S(ref.from), text: ref.deletedAt ? "" : ref.media ? "Photo" : ref.text, deleted: !!ref.deletedAt } : { unavailable: true }) : null,
    storyReply: sr ? { id: S(sr.story), media: sr.media || "", text: sr.text || "", expired: !sr.expiresAt || sr.expiresAt < new Date() } : null
  };
};
const sendGuard = async (req, toId) => {
  if (await Block.exists({ blocker: toId, blocked: req.user._id })) return "You can't message this person.";
  if (await Block.exists({ blocker: req.user._id, blocked: toId })) return "Unblock this person to message them.";
  return null;
};

router.get("/messages/:userId", auth, async (req, res) => {
  if (!isId(req.params.userId)) return res.status(400).json({ error: "Invalid user." });
  const me = req.user._id, other = req.params.userId;
  const rows = (await Message.find({ $or: [{ from: me, to: other }, { from: other, to: me }] }).sort({ createdAt: -1 }).limit(200)).reverse();
  await Message.updateMany({ from: other, to: me, readAt: null }, { $set: { readAt: new Date() } });
  await Notification.updateMany({ recipient: me, actor: other, type: { $in: ["message", "story_reply"] }, readAt: null }, { $set: { readAt: new Date() } });
  const refs = new Map((await Message.find({ _id: { $in: rows.map(m => m.replyTo).filter(Boolean) } })).map(m => [S(m._id), m]));
  res.json(rows.map(m => shapeMsg(m, refs, me)));
});

router.post("/messages/:userId", auth, async (req, res) => {
  const text = clean(req.body?.text);
  if (!isId(req.params.userId)) return res.status(400).json({ error: "Invalid user." });
  if (!text || text.length > 2000) return res.status(400).json({ error: "Message must be 1–2000 characters." });
  if (S(req.user._id) === req.params.userId) return res.status(400).json({ error: "You cannot message yourself." });
  const to = await User.findById(req.params.userId);
  if (!to) return res.status(404).json({ error: "User not found." });
  const blockedMsg = await sendGuard(req, to._id);
  if (blockedMsg) return res.status(403).json({ error: blockedMsg });
  let replyTo;
  if (req.body?.replyTo && isId(req.body.replyTo)) {
    const ref = await Message.findById(req.body.replyTo);
    if (ref && [S(ref.from), S(ref.to)].includes(S(req.user._id)) && [S(ref.from), S(ref.to)].includes(S(to._id))) replyTo = ref._id;
  }
  const m = await Message.create({ from: req.user._id, to: to._id, text, replyTo });
  await notify(req, { recipient: to._id, actor: req.user._id, type: "message", body: `${req.user.username} sent you a message.`, messageRef: m._id });
  const evt = { id: S(m._id), from: S(req.user._id), to: S(to._id) };
  emit(req, to._id, "message:new", evt); emit(req, req.user._id, "message:new", evt);
  res.status(201).json({ id: S(m._id) });
});

router.post("/messages/:userId/image", auth, upload.single("f"), async (req, res) => {
  if (!isId(req.params.userId)) return res.status(400).json({ error: "Invalid user." });
  if (!req.file || !req.file.mimetype.startsWith("image/")) return res.status(400).json({ error: "Choose a photo to send." });
  if (req.file.size > 10 * MB) return res.status(400).json({ error: "Photo is too large (10MB max)." });
  if (S(req.user._id) === req.params.userId) return res.status(400).json({ error: "You cannot message yourself." });
  const to = await User.findById(req.params.userId);
  if (!to) return res.status(404).json({ error: "User not found." });
  const blockedMsg = await sendGuard(req, to._id);
  if (blockedMsg) return res.status(403).json({ error: blockedMsg });
  const viewOnce = String(req.body.viewOnce) === "1" || req.body.viewOnce === "true";
  const caption = clean(req.body.text).slice(0, 200);
  const m = await Message.create({ from: req.user._id, to: to._id, text: caption || "Photo", media: await saveFile(req.file), viewOnce });
  await notify(req, { recipient: to._id, actor: req.user._id, type: "message", body: `${req.user.username} sent you a ${viewOnce ? "view-once " : ""}photo.`, messageRef: m._id });
  const evt = { id: S(m._id), from: S(req.user._id), to: S(to._id) };
  emit(req, to._id, "message:new", evt); emit(req, req.user._id, "message:new", evt);
  res.status(201).json({ id: S(m._id) });
});

router.post("/messages/:id/view", auth, async (req, res) => {
  if (!isId(req.params.id)) return res.status(404).json({ error: "Not found." });
  const m = await Message.findOne({ _id: req.params.id, to: req.user._id, viewOnce: true, media: { $exists: true } });
  if (!m || m.deletedAt) return res.status(404).json({ error: "This photo is no longer available." });
  if (m.viewedAt) return res.status(410).json({ error: "This photo has already been opened." });
  m.viewedAt = new Date(); await m.save();
  const evt = { id: S(m._id), from: S(m.from), to: S(m.to) };
  emit(req, m.from, "message:update", evt);
  res.json({ url: m.media, seconds: 10 });
});

/* ================= SUPPORT BOT (site help + post/people search) ================= */
const KB = [
  { k: ["post", "posting", "create post", "upload", "photo", "video", "crop", "trim"], a: "Go to Home, type in the box (up to 500 characters) and add up to 3 photos (10MB each, with crop) or one video of 15 seconds (with trim). Preview it, then tap Post.", go: "home" },
  { k: ["edit post", "edit my post", "change post", "delete post", "remove post"], a: "Tap the three dots at the top-right of your post. You can edit for the first 3 hours; after that you can only delete it.", go: "home" },
  { k: ["comment", "reply", "like comment"], a: "Tap the comment icon under a post. Use Reply to answer a comment, the heart on the right to like it, and 'View replies' to open the replies.", go: "home" },
  { k: ["story", "stories", "status"], a: "On Home, tap your circle with the + to add a story. Everything you post in 24 hours stays inside one circle. Others can reply to it and the reply lands in your Inbox.", go: "home" },
  { k: ["sell", "listing", "market", "marketplace", "renew", "expire", "mark sold"], a: "Open Market, tap Sell, add a title, price, description and up to 6 photos. Listings are live for 30 hours; renew them from 'My listings' within 3 days or they're deleted. You can also mark items as sold.", go: "market" },
  { k: ["message", "dm", "inbox", "chat", "text someone"], a: "Open Inbox or tap the message icon on any post, profile or listing. Press and hold a message to reply, like, copy or delete it.", go: "inbox" },
  { k: ["view once", "once", "disappearing", "send photo", "send image"], a: "In a chat, tap the photo button, pick an image, preview it, and switch on View once. The receiver can open it one time for 10 seconds.", go: "inbox" },
  { k: ["last seen", "online", "typing"], a: "In a chat you'll see Online, 'typing…' or last seen time. If you switch off Last seen in Settings > Privacy, others won't see yours.", go: "settings" },
  { k: ["block", "unblock", "blocked"], a: "Open the person's profile or chat, tap the three dots, then Block. Blocked people can still view your profile but can't message, comment on your posts or become your disciple. Unblock from the same menu or Settings > Blocked accounts.", go: "settings" },
  { k: ["disciple", "disciples", "follow", "unfollow", "followers"], a: "Open someone's profile and tap 'Be a disciple' to follow them. Tap again to unfollow.", go: "home" },
  { k: ["rate", "rating", "stars", "review"], a: "Open someone's profile and tap the stars to rate them from 1 to 5. Tap your same rating again to remove it.", go: "home" },
  { k: ["profile", "bio", "edit profile", "photo", "avatar", "course", "year"], a: "Go to You > Edit profile to add your bio, place of stay, hobbies, website and (students) course and year. Everything is optional.", go: "profile" },
  { k: ["privacy", "hide age", "hide", "lock posts", "private"], a: "Settings > Privacy lets you show or hide your age, course & year, last seen and online status, and lock your posts so only you can see them.", go: "settings" },
  { k: ["password", "forgot", "reset", "change password"], a: "On the login screen tap 'Forgot password?' and enter your email to get a 6-digit code. You can request up to 3 codes per day. Logged in? Use Settings > Password.", go: "settings" },
  { k: ["verify", "verification", "badge", "verified"], a: "The green badge shows a verified account. Badges are given by the Bara Cee team after checking, for example by visiting a business in person.", go: "home" },
  { k: ["signup", "sign up", "register", "email", "otp", "code"], a: "Sign up with a username, email and password (6+ characters). We email a 6-digit code; your account is only created after you enter it. Codes expire in 10 minutes.", go: "home" },
  { k: ["share", "whatsapp", "instagram", "link"], a: "Tap the share icon on a post. You get a green Bara Cee card you can send to WhatsApp, Instagram or save, plus a link that opens the exact post.", go: "home" },
  { k: ["notification", "alerts", "bell"], a: "The bell shows likes, comments, replies, messages and new disciples. Tap one to jump straight to it.", go: "notifs" },
  { k: ["support", "help", "report", "contact", "problem"], a: "Go to Settings > Support, type your message (150 characters) and submit it to the team.", go: "settings" },
  { k: ["search", "find people", "find"], a: "Use the magnifier at the top to search people and posts, or ask me: paste a @username or describe a post.", go: "home" }
];
const STOP = new Set("the a an is are was were what who whom did does do about post posts posted show me find search tell more of by on in to for and or with user person that this from old describe has have said wrote write please him her his their they it i you my can any anything something where when how why which".split(" "));
const tokens = q => [...new Set(q.toLowerCase().replace(/@[a-z0-9_.]+/g, " ").split(/[^a-z0-9#_]+/).filter(w => w.length > 2 && !STOP.has(w)))].slice(0, 6);
const kbMatch = q => {
  const l = q.toLowerCase(); let best = null, score = 0;
  for (const e of KB) { const s = e.k.filter(k => l.includes(k)).reduce((n, k) => n + (k.includes(" ") ? 2 : 1), 0); if (s > score) { score = s; best = e; } }
  return { best, score };
};

router.post("/ai", auth, async (req, res) => {
  const q = clean(req.body?.text).slice(0, 200);
  const scope = ["all", "posts", "people", "market", "help"].includes(req.body?.scope) ? req.body.scope : "all";
  if (!q) return res.status(400).json({ error: "Ask me something first." });
  const lower = q.toLowerCase(), me = req.user._id;
  const hidden = await hiddenUsers(req.user);
  const suggestions = ["How do I post?", "How do I sell an item?", "How do I block someone?"];
  const userCard = u => ({ kind: "user", id: S(u._id), username: u.username, displayName: u.displayName || "", type: u.type, avatar: u.avatar, verified: !!u.verified });
  const postRes = ps => ps.map(p => ({ kind: "post", id: S(p._id), text: p.text.slice(0, 140), createdAt: p.createdAt, user: { id: S(p.user._id || p.user), username: p.user.username } }));

  // 1) @username (or a bare username) -> person summary + their public posts
  const m = lower.match(/@([a-z0-9_.]{3,20})/);
  const bare = !m && /^[a-z0-9_.]{3,20}$/.test(lower) ? lower : null;
  if ((scope === "all" || scope === "people" || scope === "posts") && (m || bare)) {
    const u = await User.findOne({ username: m ? m[1] : bare, emailVerified: true });
    if (u) {
      const [disc, agg, count] = await Promise.all([Disciple.countDocuments({ following: u._id }), Rating.aggregate([{ $match: { target: u._id } }, { $group: { _id: null, avg: { $avg: "$stars" }, n: { $sum: 1 } } }]), Post.countDocuments({ user: u._id })]);
      const isMe = S(u._id) === S(me), edu = isMe || u.showEducation !== false;
      const bits = [`@${u.username} is a ${u.type}${u.verified ? " (verified)" : ""}.`];
      if (u.bio) bits.push(`Bio: ${u.bio}`);
      if (u.type === "student" && edu && (u.course || u.yearOfStudy)) bits.push(`Studies ${[u.course, u.yearOfStudy].filter(Boolean).join(", ")}.`);
      if (u.stay) bits.push(`Stays at ${u.stay}.`);
      if (u.hobbies) bits.push(`Hobbies: ${u.hobbies}.`);
      if (isMe || u.showAge) if (u.age) bits.push(`Age ${u.age}.`);
      bits.push(`${disc} disciple${disc === 1 ? "" : "s"}, ${count} post${count === 1 ? "" : "s"}${agg[0] ? `, rated ${Math.round(agg[0].avg * 10) / 10}/5 by ${agg[0].n}` : ""}.`);
      let results = [userCard(u)];
      if (u.lockPosts && !isMe) bits.push("Their posts are locked.");
      else {
        const rest = tokens(q.replace(/@[a-z0-9_.]+/g, ""));
        let posts = await Post.find({ user: u._id }).populate("user", "username").sort({ createdAt: -1 }).limit(40);
        if (rest.length) { const sc = p => rest.filter(t => p.text.toLowerCase().includes(t)).length; posts = posts.map(p => [sc(p), p]).filter(x => x[0] > 0).sort((a, b) => b[0] - a[0]).map(x => x[1]); }
        posts = posts.slice(0, 4);
        if (posts.length) { bits.push(rest.length ? "Matching posts:" : "Latest posts:"); results = results.concat(postRes(posts)); }
        else if (rest.length) bits.push("I couldn't find a post from them matching that.");
      }
      return res.json({ reply: bits.join(" "), results, suggestions });
    }
  }

  // 2) site help
  const kb = kbMatch(q);
  const howTo = /^(how|where|what is|what's|can i|can't|cannot|why|help|guide|steps|is there|do i|does)\b/.test(lower) || lower.endsWith("?");
  if (scope === "help" || (scope === "all" && kb.best && (kb.score >= 2 || howTo))) {
    if (kb.best) return res.json({ reply: kb.best.a, go: kb.best.go, results: [], suggestions });
    if (scope === "help") return res.json({ reply: "I couldn't find that in the guide. Try words like post, sell, story, block, privacy or password — or use Settings > Support to message the team.", results: [], suggestions });
  }

  // 3) search posts / people / listings
  const toks = tokens(q);
  if (!toks.length) return res.json({ reply: "Try a few more words, or paste a @username.", results: [], suggestions });
  const r = new RegExp(toks.map(rx).join("|"), "i");
  const results = []; let reply = "";
  if (scope === "all" || scope === "posts") {
    let posts = await Post.find({ user: { $nin: hidden }, text: r }).populate("user", "username").sort({ createdAt: -1 }).limit(80);
    posts = posts.map(p => [toks.filter(t => p.text.toLowerCase().includes(t)).length, p]).sort((a, b) => b[0] - a[0] || b[1].createdAt - a[1].createdAt).slice(0, 5).map(x => x[1]);
    results.push(...postRes(posts));
  }
  if (scope === "all" || scope === "people") {
    const us = await User.find({ emailVerified: true, $or: [{ username: r }, { displayName: r }, { bizName: r }, { course: r }, { stay: r }, { hobbies: r }] }).limit(4);
    results.push(...us.map(userCard));
  }
  if (scope === "all" || scope === "market") {
    const ls = await Listing.find({ expiresAt: { $gt: new Date() }, sold: { $ne: true }, $or: [{ title: r }, { description: r }] }).populate("user", "username").limit(4);
    results.push(...ls.map(l => ({ kind: "listing", id: S(l._id), title: l.title, price: l.price, seller: l.user?.username || "" })));
  }
  reply = results.length ? `Here's what I found for “${q}”. Tap a result to open it.` : `I couldn't find anything for “${q}”. Try different words, switch the filter, or paste a @username.`;
  res.json({ reply, results, suggestions });
});

/* ================= ADMIN: toggle the verified badge (any user) ================= */
const adminOk = req => process.env.ADMIN_VERIFY_KEY && req.headers["x-admin-key"] === process.env.ADMIN_VERIFY_KEY;
router.post("/admin/verify/:userId", async (req, res) => {
  if (!adminOk(req) || !isId(req.params.userId)) return res.status(403).json({ error: "Forbidden." });
  const u = await User.findByIdAndUpdate(req.params.userId, { verified: true }, { new: true });
  u ? res.json({ ok: true, username: u.username }) : res.status(404).json({ error: "User not found." });
});
router.post("/admin/unverify/:userId", async (req, res) => {
  if (!adminOk(req) || !isId(req.params.userId)) return res.status(403).json({ error: "Forbidden." });
  const u = await User.findByIdAndUpdate(req.params.userId, { verified: false }, { new: true });
  u ? res.json({ ok: true, username: u.username }) : res.status(404).json({ error: "User not found." });
});

module.exports = router;