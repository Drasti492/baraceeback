const express = require("express");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const crypto = require("crypto");
const multer = require("multer");
const path = require("path");
const fs = require("fs");
const router = express.Router();
const User = require("../models/User");
const Post = require("../models/Post");
const Story = require("../models/Story");
const Listing = require("../models/Listing");
const Message = require("../models/Message");
const Notification = require("../models/Notification");
const auth = require("../middleware/auth");
const { makeOtp, hashOtp } = require("../utils/otp");
const { sendVerificationEmail } = require("../utils/email");

const storage = multer.diskStorage({
  destination: (_req, _file, cb) => cb(null, path.join(__dirname, "..", "uploads")),
  filename: (_req, file, cb) => cb(null, `${Date.now()}-${crypto.randomBytes(8).toString("hex")}${path.extname(file.originalname).toLowerCase()}`)
});
const upload = multer({ storage, limits: { fileSize: 15 * 1024 * 1024 }, fileFilter: (_req, file, cb) => {
  const ok = /^(image\/(jpeg|png|webp|gif)|video\/(mp4|webm|quicktime))$/.test(file.mimetype);
  cb(ok ? null : new Error("Only JPG, PNG, WEBP, GIF, MP4 or WEBM files are allowed."), ok);
}});
const urlFor = req => req.file ? `/uploads/${req.file.filename}` : undefined;
const publicUser = u => ({ id: String(u._id), username: u.username, email: u.email, type: u.type, bizName: u.bizName, verified: u.verified, avatar: u.avatar, online: !!u.online });
const issueToken = u => jwt.sign({ sub: String(u._id) }, process.env.JWT_SECRET, { expiresIn: process.env.JWT_EXPIRES_IN || "30d" });
const clean = s => String(s || "").trim();

async function createNotification({ recipient, actor, type, body, post, messageRef, story }) {
  if (!recipient) return;

  // Prevent users from notifying themselves.
  if (actor && String(recipient) === String(actor)) return;

  try {
    await Notification.create({
      recipient,
      actor,
      type,
      body,
      post,
      messageRef,
      story
    });
  } catch (error) {
    // Notification failure must not prevent the main action.
    console.error("Notification creation failed:", error.message);
  }
}

router.post("/auth/signup", async (req, res) => {
  try {
    const { username, email, password, type, bizName, bizLocation, bizPermit } = req.body || {};
    const uname = clean(username).toLowerCase(), mail = clean(email).toLowerCase();
    if (!/^[a-z0-9_.]{3,20}$/.test(uname)) return res.status(400).json({ error: "Username must be 3–20 letters, numbers, dots or underscores." });
    if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(mail)) return res.status(400).json({ error: "Enter a valid email address." });
    if (typeof password !== "string" || password.length < 10) return res.status(400).json({ error: "Use a password of at least 10 characters." });
    if (!["student", "business", "community"].includes(type)) return res.status(400).json({ error: "Choose Student, Business or Community." });
    if (type === "business" && (!clean(bizName) || !clean(bizLocation))) return res.status(400).json({ error: "Business name and location are required." });
    if (await User.findOne({ $or: [{ username: uname }, { email: mail }] })) return res.status(409).json({ error: "That username or email is already registered." });

    const code = makeOtp();
    const user = await User.create({
      username: uname, email: mail, passwordHash: await bcrypt.hash(password, 12), type,
      bizName: type === "business" ? clean(bizName) : undefined,
      bizLocation: type === "business" ? clean(bizLocation) : undefined,
      bizPermit: type === "business" ? clean(bizPermit) : undefined,
      emailVerified: false, verified: false, otpHash: hashOtp(code),
      otpExpiresAt: new Date(Date.now() + 10 * 60 * 1000), otpAttempts: 0
    });
    try { await sendVerificationEmail(mail, code); }
    catch (mailErr) {
      await User.deleteOne({ _id: user._id });
      console.error("Brevo send failed:", mailErr.response?.data || mailErr.message);
      return res.status(502).json({ error: "We could not send your verification email. Check Brevo sender/API settings and try again." });
    }
    return res.status(201).json({ ok: true, requiresVerification: true, email: mail, message: "Verification code sent." });
  } catch (e) {
    if (e.code === 11000) return res.status(409).json({ error: "Username or email is already registered." });
    console.error("Signup error:", e.message);
    return res.status(500).json({ error: "Could not create your account." });
  }
});

router.post("/auth/verify-email", async (req, res) => {
  const email = clean(req.body?.email).toLowerCase(), code = clean(req.body?.code);
  if (!email || !/^\d{6}$/.test(code)) return res.status(400).json({ error: "Enter your email and the 6-digit code." });
  const user = await User.findOne({ email }).select("+otpHash +otpExpiresAt +otpAttempts");
  if (!user) return res.status(400).json({ error: "Invalid email or code." });
  if (user.emailVerified) return res.json({ ok: true, message: "Email already verified. Please log in." });
  if (user.otpAttempts >= 5) return res.status(429).json({ error: "Too many attempts. Request a new code." });
  if (!user.otpExpiresAt || user.otpExpiresAt < new Date()) return res.status(400).json({ error: "Code expired. Request a new one." });
  user.otpAttempts += 1;
  if (user.otpHash !== hashOtp(code)) { await user.save(); return res.status(400).json({ error: "Incorrect verification code." }); }
  user.emailVerified = true; user.otpHash = undefined; user.otpExpiresAt = undefined; user.otpAttempts = 0;
  await user.save();
  res.json({ ok: true, message: "Email verified. You can now log in." });
});

router.post("/auth/resend-code", async (req, res) => {
  const email = clean(req.body?.email).toLowerCase();
  const user = await User.findOne({ email }).select("+otpHash +otpExpiresAt +otpAttempts");
  if (!user) return res.json({ ok: true, message: "If the account exists, a new code will be sent." });
  if (user.emailVerified) return res.status(400).json({ error: "This email is already verified. Please log in." });
  const code = makeOtp();
  user.otpHash = hashOtp(code); user.otpExpiresAt = new Date(Date.now() + 10*60*1000); user.otpAttempts = 0;
  await user.save();
  try { await sendVerificationEmail(email, code); }
  catch (e) { console.error("Brevo resend failed:", e.response?.data || e.message); return res.status(502).json({ error: "Could not send email. Try again later." }); }
  res.json({ ok: true, message: "A new code has been sent." });
});

router.post("/auth/login", async (req, res) => {
  const username = clean(req.body?.username).toLowerCase(), password = req.body?.password;
  const user = await User.findOne({ username }).select("+passwordHash");
  if (!user || !await bcrypt.compare(String(password || ""), user.passwordHash)) return res.status(401).json({ error: "Incorrect username or password." });
  if (!user.emailVerified) return res.status(403).json({ error: "Please verify your email before logging in." });
  user.online = true; user.lastSeen = new Date(); await user.save();
  res.json({ token: issueToken(user), user: publicUser(user) });
});

router.get("/me", auth, (req, res) => res.json(publicUser(req.user)));
router.post("/ping", auth, async (req, res) => { req.user.online = true; req.user.lastSeen = new Date(); await req.user.save(); res.json({ ok: true }); });

router.get("/online", auth, async (_req, res) => {
  const users = await User.find({ online: true }).sort({ lastSeen: -1 }).limit(30);
  res.json(users.map(publicUser));
});
router.get("/trending", auth, async (_req, res) => {
  const rows = await Post.aggregate([{ $match: { createdAt: { $gte: new Date(Date.now()-7*86400000) } } }, { $project: { tags: { $regexFindAll: { input: "$text", regex: /#([\\w]+)/ } } } }, { $unwind: "$tags" }, { $group: { _id: { $toLower: { $arrayElemAt: ["$tags.captures", 0] } }, n: { $sum: 1 } } }, { $sort: { n: -1 } }, { $limit: 10 }]);
  res.json(rows);
});

router.post("/posts", auth, upload.single("f"), async (req, res) => {
  const text = clean(req.body.text);
  if (!text && !req.file) return res.status(400).json({ error: "Write something or attach media." });
  const post = await Post.create({ user: req.user._id, text, media: urlFor(req) });
  res.status(201).json({ id: post.id });
});


router.get("/posts", auth, async (req, res) => {
  const filter = {};

  if (req.query.tag) {
    filter.text = {
      $regex: `#${String(req.query.tag).replace(/[.*+?^${}()|[\]\\]/g, "\\$&")}`,
      $options: "i"
    };
  }

  const type = req.query.type;

  let query = Post.find(filter).populate("user");

  if (type && ["student", "business", "community"].includes(type)) {
    const ids = await User.find({ type }).distinct("_id");

    filter.user = { $in: ids };

    query = Post.find(filter).populate("user");
  }

  const sort =
    req.query.sort === "oldest"
      ? { createdAt: 1 }
      : req.query.sort === "popular"
        ? { likes: -1, createdAt: -1 }
        : { createdAt: -1 };

  const posts = await query.sort(sort).limit(60);

  res.json(
    posts.map(p => ({
      id: String(p._id),
      text: p.text,
      media: p.media,
      createdAt: p.createdAt,
      likes: p.likes.length,

      // Check whether the logged-in user liked this post.
      likedByMe: p.likes.some(
        x => String(x) === String(req.user._id)
      ),

      comments: p.comments.map(c => ({
        user: c.username,
        text: c.text
      })),

      user: publicUser(p.user)
    }))
  );
});


// LIKE / UNLIKE POSTS
router.post("/posts/:id/like", auth, async (req, res) => {
  const p = await Post.findById(req.params.id);

  if (!p) {
    return res.status(404).json({
      error: "Post not found."
    });
  }

  // Check whether this user has already liked the post.
  const i = p.likes.findIndex(
    x => String(x) === String(req.user._id)
  );

  // Add the like if it doesn't exist; otherwise remove it.
  if (i < 0) {
    p.likes.push(req.user._id);
  } else {
    p.likes.splice(i, 1);
  }

  await p.save();

  // Return the updated like status and count.
  const likedByMe = p.likes.some(
    x => String(x) === String(req.user._id)
  );

  res.json({
    likes: p.likes.length,
    likedByMe
  });
});



router.post("/posts/:id/comments", auth, async (req, res) => {
  const text = clean(req.body?.text);

  if (!text || text.length > 500) {
    return res.status(400).json({
      error: "Comment must be 1–500 characters."
    });
  }

  const p = await Post.findById(req.params.id);

  if (!p) {
    return res.status(404).json({
      error: "Post not found."
    });
  }

  p.comments.push({
    user: req.user._id,
    username: req.user.username,
    text
  });

  await p.save();

  await createNotification({
    recipient: p.user,
    actor: req.user._id,
    type: "comment",
    body: `${req.user.username} commented on your post: ${text.slice(0, 120)}`,
    post: p._id
  });

  res.status(201).json({ ok: true });
});


router.post("/messages/:userId", auth, async (req, res) => {
  const text = clean(req.body?.text);

  if (!text || text.length > 2000) {
    return res.status(400).json({
      error: "Message must be 1–2000 characters."
    });
  }

  if (String(req.user._id) === req.params.userId) {
    return res.status(400).json({
      error: "You cannot message yourself."
    });
  }

  const recipient = await User.findById(req.params.userId);

  if (!recipient) {
    return res.status(404).json({
      error: "User not found."
    });
  }

  const m = await Message.create({
    from: req.user._id,
    to: recipient._id,
    text
  });

  await createNotification({
    recipient: recipient._id,
    actor: req.user._id,
    type: "message",
    body: `${req.user.username} sent you a message.`,
    messageRef: m._id
  });

  res.status(201).json({ id: m.id });
});



router.post("/stories/:id/reply", auth, async (req, res) => {
  const story = await Story.findById(req.params.id);
  const text = clean(req.body?.text);

  if (!story || story.expiresAt < new Date()) {
    return res.status(404).json({
      error: "Story expired."
    });
  }

  if (!text || text.length > 1000) {
    return res.status(400).json({
      error: "Enter a reply."
    });
  }

  const message = await Message.create({
    from: req.user._id,
    to: story.user,
    text: `Story reply: ${text}`
  });

  await createNotification({
    recipient: story.user,
    actor: req.user._id,
    type: "story_reply",
    body: `${req.user.username} replied to your story.`,
    messageRef: message._id,
    story: story._id
  });

  res.json({ ok: true });
});




router.post("/stories", auth, upload.single("f"), async (req, res) => {
  const text = clean(req.body.text); if (!text && !req.file) return res.status(400).json({ error: "Add text or media." });
  const s = await Story.create({ user: req.user._id, text, media: urlFor(req) }); res.status(201).json({ id: s.id });
});
router.get("/stories", auth, async (_req, res) => {
  const rows = await Story.find({ expiresAt: { $gt: new Date() } }).populate("user").sort({ createdAt: -1 }).limit(80);
  res.json(rows.map(s => ({ id: String(s._id), text: s.text, media: s.media, user: publicUser(s.user) })));
});


router.post("/listings", auth, upload.single("f"), async (req, res) => {
  const title = clean(req.body.title), price = Number(req.body.price);
  if (!title || title.length > 80 || !Number.isFinite(price) || price < 0) return res.status(400).json({ error: "Enter a valid title and price." });
  const activeCount = await Listing.countDocuments({ user: req.user._id, expiresAt: { $gt: new Date() } });
  if (activeCount >= 10) return res.status(403).json({ error: "You have reached the 10 active-listing limit." });
  // Paid listing fees are not charged until PayHero is configured and validated.
  const l = await Listing.create({ user: req.user._id, title, price, image: urlFor(req) });
  res.status(201).json({ id: l.id });
});
router.get("/listings", auth, async (req, res) => {
  const q = clean(req.query.q);
  const rows = await Listing.find({ expiresAt: { $gt: new Date() }, ...(q ? { title: { $regex: q.replace(/[.*+?^${}()|[\\]\\\\]/g, "\\\\$&"), $options: "i" } } : {}) }).populate("user").sort({ createdAt: -1 }).limit(100);
  res.json(rows.map(l => ({ _id: String(l._id), title: l.title, price: l.price, image: l.image, user: publicUser(l.user) })));
});
router.get("/my-listings", auth, async (req, res) => {
  const rows = await Listing.find({ user: req.user._id }).sort({ createdAt: -1 });
  res.json(rows.map(l => ({ _id: String(l._id), title: l.title, price: l.price, expiresAt: l.expiresAt, deleteAt: l.deleteAt })));
});
router.post("/listings/:id/renew", auth, async (req, res) => {
  const l = await Listing.findOne({ _id: req.params.id, user: req.user._id }); if (!l) return res.status(404).json({ error: "Listing not found." });
  if (l.deleteAt <= new Date()) return res.status(410).json({ error: "Listing retention period has ended." });
  const h = Number(process.env.LISTING_VISIBLE_HOURS || 30);
  l.expiresAt = new Date(Date.now() + h*3600000); l.deleteAt = new Date(l.expiresAt.getTime() + Number(process.env.LISTING_RETENTION_DAYS || 3)*86400000);
  await l.save(); res.json({ ok: true });
});
router.delete("/listings/:id", auth, async (req, res) => {
  const l = await Listing.findOneAndDelete({ _id: req.params.id, user: req.user._id }); if (!l) return res.status(404).json({ error: "Listing not found." });
  res.json({ ok: true });
});

router.get("/threads", auth, async (req, res) => {
  const msgs = await Message.find({ $or: [{ from: req.user._id }, { to: req.user._id }] }).sort({ createdAt: -1 }).limit(300);
  const ids = [...new Set(msgs.map(m => String(m.from) === String(req.user._id) ? String(m.to) : String(m.from)))];
  const users = await User.find({ _id: { $in: ids } });
  res.json(users.map(u => ({ id: String(u._id), username: u.username, type: u.type, avatar: u.avatar, online: u.online })));
});
router.get("/messages/:userId", auth, async (req, res) => {
  const rows = await Message.find({ $or: [{ from: req.user._id, to: req.params.userId }, { from: req.params.userId, to: req.user._id }] }).sort({ createdAt: 1 }).limit(200);
  res.json(rows.map(m => ({ from: String(m.from), text: m.text, createdAt: m.createdAt })));
});

router.get("/search", auth, async (req, res) => {
  const q = clean(req.query.q); if (q.length < 2) return res.json({ users: [], posts: [] });
  const rx = new RegExp(q.replace(/[.*+?^${}()|[\\]\\\\]/g, "\\\\$&"), "i");
  const [users, posts] = await Promise.all([User.find({ $or: [{ username: rx }, { bizName: rx }] }).limit(15), Post.find({ text: rx }).populate("user").sort({ createdAt: -1 }).limit(20)]);
  res.json({ users: users.map(publicUser), posts: posts.map(p => ({ id: String(p._id), text: p.text, user: publicUser(p.user) })) });
});
router.post("/avatar", auth, upload.single("f"), async (req, res) => {
  if (!req.file || !req.file.mimetype.startsWith("image/")) return res.status(400).json({ error: "Choose an image." });
  req.user.avatar = urlFor(req); await req.user.save(); res.json({ avatar: req.user.avatar });
});
router.post("/ai", auth, async (req, res) => {
  const q = clean(req.body?.text); if (!q) return res.status(400).json({ error: "Ask me what you are looking for." });
  const rows = await Listing.find({ expiresAt: { $gt: new Date() }, title: { $regex: q.split(/\\s+/).slice(0,4).join("|"), $options: "i" } }).limit(5);
  res.json({ reply: rows.length ? `I found ${rows.length} matching listing(s): ${rows.map(x => `${x.title} (KSh ${x.price})`).join(", ")}. Open Marketplace to contact the sellers.` : "I couldn't find a matching live listing yet. Try a shorter search or browse the Marketplace." });
});

// Business verification is manual. Call from a trusted admin terminal only.
router.post("/admin/verify-business/:userId", async (req, res) => {
  const supplied = req.headers["x-admin-key"];
  if (!process.env.ADMIN_VERIFY_KEY || !supplied || supplied !== process.env.ADMIN_VERIFY_KEY) return res.status(403).json({ error: "Forbidden." });
  const user = await User.findOne({ _id: req.params.userId, type: "business", emailVerified: true });
  if (!user) return res.status(404).json({ error: "Verified-email business account not found." });
  user.verified = true; await user.save(); res.json({ ok: true, user: publicUser(user) });
});

// Do not accept payments until PayHero credentials and current API contract are supplied and tested.
router.post("/pay", auth, async (_req, res) => res.status(503).json({ error: "Marketplace payments are not enabled yet. Contact the Bara Cee administrator." }));
router.post("/payhero/callback", async (_req, res) => res.status(503).json({ error: "Payment callback is not configured." }));

router.post("/auth/logout", auth, async (req, res) => { req.user.online = false; req.user.lastSeen = new Date(); await req.user.save(); res.json({ ok: true }); });
module.exports = router;
