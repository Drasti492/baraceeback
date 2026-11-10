// routes/extras.js  — mounted BEFORE routes/api.js so these routes take precedence.
const express = require("express");
const bcrypt = require("bcryptjs");
const axios = require("axios");
const rateLimit = require("express-rate-limit");
const router = express.Router();
const User = require("../models/User");
const Post = require("../models/Post");
const Story = require("../models/Story");
const Listing = require("../models/Listing");
const Message = require("../models/Message");
const Notification = require("../models/Notification");
const auth = require("../middleware/auth");
const { makeOtp, hashOtp } = require("../utils/otp");

const clean = s => String(s || "").trim();
const rx = s => String(s).replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
const isId = id => /^[a-f0-9]{24}$/i.test(String(id));
const S = x => String(x);

const publicUser = u => ({
  id: S(u._id), username: u.username, displayName: u.displayName || "", bio: u.bio || "",
  location: u.location || "", website: u.website || "", type: u.type, bizName: u.bizName,
  verified: u.verified, avatar: u.avatar, online: !!u.online && u.showOnlineStatus !== false
});
const privateUser = u => ({
  ...publicUser(u), email: u.email, theme: u.theme,
  showOnlineStatus: u.showOnlineStatus !== false, showLastSeen: u.showLastSeen !== false
});
const emit = (req, userId, event, payload) => {
  const io = req.app.get("io");
  if (io) io.to(`user:${userId}`).emit(event, payload);
};

async function notify(req, { recipient, actor, type, body, post, messageRef, story }) {
  if (!recipient || (actor && S(recipient) === S(actor))) return;
  try {
    if (type === "message") await Notification.deleteMany({ recipient, actor, type, readAt: null });
    if (type === "like" && await Notification.exists({ recipient, actor, type, post, readAt: null })) return;
    const n = await Notification.create({ recipient, actor, type, body, post, messageRef, story });
    emit(req, recipient, "notification:new", { id: S(n._id), type, body });
  } catch (e) { console.error("notify failed:", e.message); }
}

async function sendCode(email, code, subject, intro) {
  await axios.post("https://api.brevo.com/v3/smtp/email", {
    sender: { name: process.env.BREVO_SENDER_NAME || "Bara Cee", email: process.env.BREVO_SENDER_EMAIL },
    to: [{ email }], subject,
    htmlContent: `<div style="font-family:Arial,sans-serif;max-width:520px;margin:auto;padding:28px"><h2>Bara Cee</h2><p>${intro}</p><div style="font-size:34px;font-weight:700;letter-spacing:9px;padding:18px;background:#f3f5fa;text-align:center;border-radius:12px">${code}</div><p>This code expires in 10 minutes. If this wasn't you, ignore this email.</p></div>`
  }, { headers: { "api-key": process.env.BREVO_API_KEY, "Content-Type": "application/json" }, timeout: 15000 });
}

/* ---------------- ACCOUNT / PROFILE / SETTINGS ---------------- */
router.get("/me", auth, (req, res) => res.json(privateUser(req.user)));

router.get("/users/check-username",
  rateLimit({ windowMs: 60000, limit: 60, standardHeaders: true, legacyHeaders: false }),
  async (req, res) => {
    const u = clean(req.query.u).toLowerCase();
    if (!/^[a-z0-9_.]{3,20}$/.test(u)) return res.json({ available: false, reason: "Use 3–20 letters, numbers, dots or underscores." });
    const taken = await User.exists({ username: u });
    res.json({ available: !taken, reason: taken ? "That username is already taken." : "" });
  });

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
  if (b.displayName !== undefined) u.displayName = clean(b.displayName).slice(0, 40);
  if (b.bio !== undefined) u.bio = clean(b.bio).slice(0, 160);
  if (b.location !== undefined) u.location = clean(b.location).slice(0, 60);
  if (b.website !== undefined) {
    let w = clean(b.website).slice(0, 100);
    if (w && !/^https?:\/\//i.test(w)) w = "https://" + w;
    u.website = w;
  }
  try { await u.save(); } catch (e) {
    if (e.code === 11000) return res.status(409).json({ error: "That username is already taken." });
    throw e;
  }
  res.json(privateUser(u));
});

router.patch("/settings", auth, async (req, res) => {
  const b = req.body || {}, u = req.user;
  if (typeof b.showOnlineStatus === "boolean") u.showOnlineStatus = b.showOnlineStatus;
  if (typeof b.showLastSeen === "boolean") u.showLastSeen = b.showLastSeen;
  if (["light", "dark", "system"].includes(b.theme)) u.theme = b.theme;
  await u.save();
  res.json(privateUser(u));
});

router.post("/auth/change-password", auth, async (req, res) => {
  const { current, password } = req.body || {};
  if (typeof password !== "string" || password.length < 10) return res.status(400).json({ error: "Use a new password of at least 10 characters." });
  const u = await User.findById(req.user._id).select("+passwordHash");
  if (!await bcrypt.compare(String(current || ""), u.passwordHash)) return res.status(401).json({ error: "Your current password is incorrect." });
  u.passwordHash = await bcrypt.hash(password, 12);
  await u.save();
  res.json({ ok: true });
});

router.post("/auth/forgot-password", async (req, res) => {
  const email = clean(req.body?.email).toLowerCase();
  const generic = { ok: true, message: "If that email is registered, a reset code has been sent." };
  const u = await User.findOne({ email, emailVerified: true }).select("+otpHash +otpExpiresAt +otpAttempts");
  if (!u) return res.json(generic);
  const code = makeOtp();
  u.otpHash = hashOtp(code); u.otpExpiresAt = new Date(Date.now() + 10 * 60000); u.otpAttempts = 0;
  await u.save();
  try { await sendCode(email, code, "Your Bara Cee password reset code", "Use this code to reset your password:"); }
  catch (e) { console.error("Reset email failed:", e.response?.data || e.message); return res.status(502).json({ error: "Could not send email. Try again later." }); }
  res.json(generic);
});

router.post("/auth/reset-password", async (req, res) => {
  const email = clean(req.body?.email).toLowerCase(), code = clean(req.body?.code), password = req.body?.password;
  if (!/^\d{6}$/.test(code)) return res.status(400).json({ error: "Enter the 6-digit code." });
  if (typeof password !== "string" || password.length < 10) return res.status(400).json({ error: "Use a password of at least 10 characters." });
  const u = await User.findOne({ email, emailVerified: true }).select("+passwordHash +otpHash +otpExpiresAt +otpAttempts");
  if (!u || !u.otpHash) return res.status(400).json({ error: "Invalid or expired code." });
  if (u.otpAttempts >= 5) return res.status(429).json({ error: "Too many attempts. Request a new code." });
  if (!u.otpExpiresAt || u.otpExpiresAt < new Date()) return res.status(400).json({ error: "Code expired. Request a new one." });
  u.otpAttempts += 1;
  if (u.otpHash !== hashOtp(code)) { await u.save(); return res.status(400).json({ error: "Incorrect code." }); }
  u.passwordHash = await bcrypt.hash(password, 12);
  u.otpHash = undefined; u.otpExpiresAt = undefined; u.otpAttempts = 0;
  await u.save();
  res.json({ ok: true, message: "Password updated. You can log in now." });
});

/* ---------------- FEED: likes + fixed trending/search/ai/online ---------------- */
router.post("/posts/:id/like", auth, async (req, res) => {
  if (!isId(req.params.id)) return res.status(404).json({ error: "Post not found." });
  const p = await Post.findById(req.params.id);
  if (!p) return res.status(404).json({ error: "Post not found." });
  const i = p.likes.findIndex(x => S(x) === S(req.user._id));
  if (i < 0) p.likes.push(req.user._id); else p.likes.splice(i, 1);
  await p.save();
  if (i < 0) await notify(req, { recipient: p.user, actor: req.user._id, type: "like", body: `${req.user.username} liked your post.`, post: p._id });
  res.json({ likes: p.likes.length, likedByMe: i < 0 });
});

router.get("/trending", auth, async (_req, res) => {
  const rows = await Post.aggregate([
    { $match: { createdAt: { $gte: new Date(Date.now() - 7 * 86400000) } } },
    { $project: { tags: { $regexFindAll: { input: "$text", regex: "#([A-Za-z0-9_]+)" } } } },
    { $unwind: "$tags" },
    { $group: { _id: { $toLower: { $arrayElemAt: ["$tags.captures", 0] } }, n: { $sum: 1 } } },
    { $sort: { n: -1 } }, { $limit: 10 }
  ]);
  res.json(rows);
});

router.get("/search", auth, async (req, res) => {
  const q = clean(req.query.q);
  if (q.length < 2) return res.json({ users: [], posts: [] });
  const r = new RegExp(rx(q), "i");
  const [users, posts] = await Promise.all([
    User.find({ emailVerified: true, $or: [{ username: r }, { bizName: r }, { displayName: r }] }).limit(15),
    Post.find({ text: r }).populate("user").sort({ createdAt: -1 }).limit(20)
  ]);
  res.json({ users: users.map(publicUser), posts: posts.map(p => ({ id: S(p._id), text: p.text, user: publicUser(p.user) })) });
});

router.get("/online", auth, async (_req, res) => {
  const users = await User.find({ online: true, showOnlineStatus: { $ne: false } }).sort({ lastSeen: -1 }).limit(30);
  res.json(users.map(publicUser));
});

router.post("/ai", auth, async (req, res) => {
  const q = clean(req.body?.text);
  if (!q) return res.status(400).json({ error: "Ask me what you are looking for." });
  const words = q.split(/\s+/).filter(w => w.length > 1).slice(0, 4).map(rx);
  if (!words.length) return res.json({ reply: "Try a longer search, like “laundry service”." });
  const rows = await Listing.find({ expiresAt: { $gt: new Date() }, sold: { $ne: true }, title: { $regex: words.join("|"), $options: "i" } }).limit(5);
  res.json({ reply: rows.length
    ? `I found ${rows.length} matching listing(s): ${rows.map(x => `${x.title} (KSh ${x.price})`).join(", ")}. Open Market to contact the sellers.`
    : "I couldn't find a matching live listing yet. Try a shorter search or browse the Market." });
});

/* ---------------- NOTIFICATIONS ---------------- */
const shapeNotif = n => ({
  id: S(n._id), type: n.type, body: n.body, readAt: n.readAt, createdAt: n.createdAt,
  post: n.post ? S(n.post) : null, story: n.story ? S(n.story) : null,
  actor: n.actor ? { id: S(n.actor._id), username: n.actor.username, avatar: n.actor.avatar, type: n.actor.type } : null
});
router.get("/notifications", auth, async (req, res) => {
  const rows = await Notification.find({ recipient: req.user._id }).populate("actor", "username avatar type").sort({ createdAt: -1 }).limit(100);
  res.json({ notifications: rows.map(shapeNotif) });
});
router.get("/notifications/unread-count", auth, async (req, res) => {
  res.json({ count: await Notification.countDocuments({ recipient: req.user._id, readAt: null }) });
});
router.patch("/notifications/read-all", auth, async (req, res) => {
  await Notification.updateMany({ recipient: req.user._id, readAt: null }, { $set: { readAt: new Date() } });
  res.json({ ok: true });
});
router.patch("/notifications/:id/read", auth, async (req, res) => {
  if (!isId(req.params.id)) return res.status(404).json({ error: "Not found." });
  await Notification.updateOne({ _id: req.params.id, recipient: req.user._id, readAt: null }, { $set: { readAt: new Date() } });
  res.json({ ok: true });
});
router.delete("/notifications/:id", auth, async (req, res) => {
  if (!isId(req.params.id)) return res.status(404).json({ error: "Not found." });
  await Notification.deleteOne({ _id: req.params.id, recipient: req.user._id });
  res.json({ ok: true });
});

/* ---------------- MESSAGES: replies, hearts, delete, story replies ---------------- */
const shapeMsg = (m, refs, meId) => {
  const ref = m.replyTo ? refs.get(S(m.replyTo)) : null;
  const sr = m.storyReply && m.storyReply.story ? m.storyReply : null;
  return {
    id: S(m._id), from: S(m.from), text: m.deletedAt ? "" : m.text, deleted: !!m.deletedAt,
    createdAt: m.createdAt, readAt: m.readAt || null,
    hearts: m.hearts.length, heartedByMe: m.hearts.some(x => S(x) === S(meId)),
    replyTo: m.replyTo ? (ref ? { id: S(ref._id), from: S(ref.from), text: ref.deletedAt ? "" : ref.text, deleted: !!ref.deletedAt } : { unavailable: true }) : null,
    storyReply: sr ? { id: S(sr.story), media: sr.media || "", text: sr.text || "", expired: !sr.expiresAt || sr.expiresAt < new Date() } : null
  };
};

router.get("/threads", auth, async (req, res) => {
  const me = S(req.user._id);
  const msgs = await Message.find({ $or: [{ from: me }, { to: me }] }).sort({ createdAt: -1 }).limit(500);
  const map = new Map();
  for (const m of msgs) {
    const other = S(m.from) === me ? S(m.to) : S(m.from);
    if (!map.has(other)) map.set(other, { last: m, unread: 0 });
    if (S(m.to) === me && !m.readAt) map.get(other).unread++;
  }
  const users = await User.find({ _id: { $in: [...map.keys()] } });
  const out = users.map(u => {
    const t = map.get(S(u._id));
    const preview = t.last.deletedAt ? "Message deleted" : (t.last.storyReply?.story ? "Story reply" : t.last.text);
    return { ...publicUser(u), last: preview.slice(0, 40), unread: t.unread, at: t.last.createdAt };
  }).sort((a, b) => new Date(b.at) - new Date(a.at));
  res.json(out);
});

router.get("/messages/:userId", auth, async (req, res) => {
  if (!isId(req.params.userId)) return res.status(400).json({ error: "Invalid user." });
  const me = req.user._id, other = req.params.userId;
  const rows = (await Message.find({ $or: [{ from: me, to: other }, { from: other, to: me }] }).sort({ createdAt: -1 }).limit(200)).reverse();
  await Message.updateMany({ from: other, to: me, readAt: null }, { $set: { readAt: new Date() } });
  await Notification.updateMany({ recipient: me, actor: other, type: { $in: ["message", "story_reply"] }, readAt: null }, { $set: { readAt: new Date() } });
  const ids = rows.map(m => m.replyTo).filter(Boolean);
  const refs = new Map((await Message.find({ _id: { $in: ids } })).map(m => [S(m._id), m]));
  res.json(rows.map(m => shapeMsg(m, refs, me)));
});

router.post("/messages/:userId", auth, async (req, res) => {
  const text = clean(req.body?.text);
  if (!isId(req.params.userId)) return res.status(400).json({ error: "Invalid user." });
  if (!text || text.length > 2000) return res.status(400).json({ error: "Message must be 1–2000 characters." });
  if (S(req.user._id) === req.params.userId) return res.status(400).json({ error: "You cannot message yourself." });
  const to = await User.findById(req.params.userId);
  if (!to) return res.status(404).json({ error: "User not found." });
  let replyTo;
  if (req.body?.replyTo) {
    if (!isId(req.body.replyTo)) return res.status(400).json({ error: "Invalid reply." });
    const ref = await Message.findById(req.body.replyTo);
    const pair = ref && [S(ref.from), S(ref.to)];
    if (ref && pair.includes(S(req.user._id)) && pair.includes(S(to._id))) replyTo = ref._id;
  }
  const m = await Message.create({ from: req.user._id, to: to._id, text, replyTo });
  await notify(req, { recipient: to._id, actor: req.user._id, type: "message", body: `${req.user.username} sent you a message.`, messageRef: m._id });
  const evt = { id: S(m._id), from: S(req.user._id), to: S(to._id) };
  emit(req, to._id, "message:new", evt); emit(req, req.user._id, "message:new", evt);
  res.status(201).json({ id: S(m._id) });
});

router.delete("/messages/:id", auth, async (req, res) => {
  if (!isId(req.params.id)) return res.status(404).json({ error: "Not found." });
  const m = await Message.findOne({ _id: req.params.id, from: req.user._id });
  if (!m) return res.status(404).json({ error: "Message not found." });
  m.deletedAt = new Date(); m.text = "[deleted]"; m.hearts = []; await m.save();
  const evt = { id: S(m._id), from: S(m.from), to: S(m.to) };
  emit(req, m.to, "message:update", evt); emit(req, m.from, "message:update", evt);
  res.json({ ok: true });
});

router.put("/messages/:id/heart", auth, async (req, res) => {
  if (!isId(req.params.id)) return res.status(404).json({ error: "Not found." });
  const m = await Message.findById(req.params.id);
  const me = S(req.user._id);
  if (!m || ![S(m.from), S(m.to)].includes(me) || m.deletedAt) return res.status(404).json({ error: "Message not found." });
  const i = m.hearts.findIndex(x => S(x) === me);
  if (i < 0) m.hearts.push(req.user._id); else m.hearts.splice(i, 1);
  await m.save();
  const evt = { id: S(m._id), from: S(m.from), to: S(m.to) };
  emit(req, m.to, "message:update", evt); emit(req, m.from, "message:update", evt);
  res.json({ hearts: m.hearts.length });
});

router.post("/stories/:id/reply", auth, async (req, res) => {
  if (!isId(req.params.id)) return res.status(404).json({ error: "Story expired." });
  const story = await Story.findById(req.params.id);
  const text = clean(req.body?.text);
  if (!story || story.expiresAt < new Date()) return res.status(404).json({ error: "Story expired." });
  if (S(story.user) === S(req.user._id)) return res.status(400).json({ error: "You cannot reply to your own story." });
  if (!text || text.length > 1000) return res.status(400).json({ error: "Enter a reply." });
  const m = await Message.create({
    from: req.user._id, to: story.user, text,
    storyReply: { story: story._id, media: story.media, text: story.text, expiresAt: story.expiresAt }
  });
  await notify(req, { recipient: story.user, actor: req.user._id, type: "story_reply", body: `${req.user.username} replied to your story.`, messageRef: m._id, story: story._id });
  const evt = { id: S(m._id), from: S(req.user._id), to: S(story.user) };
  emit(req, story.user, "message:new", evt); emit(req, req.user._id, "message:new", evt);
  res.json({ ok: true });
});

/* ---------------- LISTINGS: edit, sold, richer lists ---------------- */
const shapeListing = l => ({ _id: S(l._id), title: l.title, price: l.price, image: l.image, description: l.description || "", sold: !!l.sold, expiresAt: l.expiresAt, deleteAt: l.deleteAt });
router.get("/listings", auth, async (req, res) => {
  const q = clean(req.query.q);
  const filter = { expiresAt: { $gt: new Date() }, sold: { $ne: true } };
  if (q) filter.title = { $regex: rx(q), $options: "i" };
  const rows = await Listing.find(filter).populate("user").sort({ createdAt: -1 }).limit(100);
  res.json(rows.map(l => ({ ...shapeListing(l), user: publicUser(l.user) })));
});
router.get("/my-listings", auth, async (req, res) => {
  res.json((await Listing.find({ user: req.user._id }).sort({ createdAt: -1 })).map(shapeListing));
});
router.patch("/listings/:id", auth, async (req, res) => {
  if (!isId(req.params.id)) return res.status(404).json({ error: "Listing not found." });
  const l = await Listing.findOne({ _id: req.params.id, user: req.user._id });
  if (!l) return res.status(404).json({ error: "Listing not found." });
  const b = req.body || {};
  if (b.title !== undefined) { const t = clean(b.title); if (!t || t.length > 80) return res.status(400).json({ error: "Title must be 1–80 characters." }); l.title = t; }
  if (b.price !== undefined) { const p = Number(b.price); if (!Number.isFinite(p) || p < 0) return res.status(400).json({ error: "Enter a valid price." }); l.price = p; }
  if (b.description !== undefined) l.description = clean(b.description).slice(0, 500);
  await l.save();
  res.json(shapeListing(l));
});
router.post("/listings/:id/sold", auth, async (req, res) => {
  if (!isId(req.params.id)) return res.status(404).json({ error: "Listing not found." });
  const l = await Listing.findOne({ _id: req.params.id, user: req.user._id });
  if (!l) return res.status(404).json({ error: "Listing not found." });
  l.sold = req.body?.sold !== false; await l.save();
  res.json({ ok: true, sold: l.sold });
});

module.exports = router;