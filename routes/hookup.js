// routes/hookup.js — adults-only, anonymous-ID section. Mounted at /api/hookup.
const express = require("express");
const crypto = require("crypto");
const rateLimit = require("express-rate-limit");
const router = express.Router();
const User = require("../models/User");
const auth = require("../middleware/auth");
const { HookupProfile, HookupPost, HookupMessage, HookupReveal, HookupBlock, HookupReport } = require("../models/Hookup");
const { clean, rx, isId, S } = require("../utils/helpers");

const GENDERS = ["male", "female"], STATUSES = ["single", "complicated"], LOOKING = ["relationship", "dating", "friendship", "casual", "buddy"], INTERESTED = ["men", "women", "everyone"];
const REASONS = ["spam", "harassment", "underage", "scam", "other"];
const userLimit = (windowMs, limit) => rateLimit({ windowMs, limit, standardHeaders: true, legacyHeaders: false, keyGenerator: req => S(req.user?._id || req.ip), validate: false, message: { error: "You're doing that too fast. Please slow down." } });

/* ---------- safety filters ---------- */
const BAD_ALL = /(escort|sponsor|sugar\s*(daddy|mummy|mommy|mama)|under\s*-?\s*age|school\s*(girl|boy)|high\s*school|\bminors?\b|nudes?\b|sex\s*for|per\s*(night|hour)|pay\s*for|for\s*money)/i;
const BAD_PUBLIC = /(https?:\/\/|www\.|whats\s*app|telegram|\+?\d[\d\s-]{8,}|@\w+\.\w+)/i;
const blocked = (t, pub) => BAD_ALL.test(t) || (pub && BAD_PUBLIC.test(t));

const ageOf = d => { const n = new Date(), b = new Date(d); let a = n.getFullYear() - b.getFullYear(); if (n < new Date(n.getFullYear(), b.getMonth(), b.getDate())) a--; return a; };
const card = p => ({ alias: p.alias, gender: p.gender, age: p.birthDate ? ageOf(p.birthDate) : null, status: p.status, lookingFor: p.lookingFor, interestedIn: p.interestedIn, bio: p.bio, interests: p.interests, area: p.area, joinedAt: p.createdAt });
// attach the real username ONLY when the person chose to show it publicly
async function withNames(profiles) {
  const ids = profiles.filter(p => p.showUsername).map(p => p.user);
  const users = ids.length ? await User.find({ _id: { $in: ids } }).select("username displayName type") : [];
  const m = new Map(users.map(u => [S(u._id), u]));
  return profiles.map(p => { const u = p.showUsername ? m.get(S(p.user)) : null; return { ...card(p), ...(u ? { username: u.username, userId: S(u._id) } : {}) }; });
}

/* ---------- guards ---------- */
async function needProfile(req, res, next) {
  const hp = await HookupProfile.findOne({ user: req.user._id }).select("+birthDate");
  if (!hp) return res.status(403).json({ error: "Join Hookup first.", code: "no_profile" });
  if (hp.flagged) return res.status(403).json({ error: "Your Hookup access is under review.", code: "flagged" });
  req.hp = hp; next();
}
const hiddenIds = async hp => {
  const [a, b] = await Promise.all([HookupBlock.find({ blocker: hp._id }).distinct("blocked"), HookupBlock.find({ blocked: hp._id }).distinct("blocker")]);
  return [...a, ...b];
};
const byAlias = alias => HookupProfile.findOne({ alias: clean(alias).toUpperCase() }).select("+birthDate");
const isBlockedPair = (a, b) => HookupBlock.exists({ $or: [{ blocker: a, blocked: b }, { blocker: b, blocked: a }] });

/* ---------- join / profile ---------- */
router.get("/me", auth, async (req, res) => {
  const hp = await HookupProfile.findOne({ user: req.user._id }).select("+birthDate");
  if (!hp) return res.json({ joined: false });
  res.json({ joined: true, flagged: hp.flagged, profile: { ...card(hp), active: hp.active, showUsername: hp.showUsername } });
});

router.post("/join", auth, async (req, res) => {
  if (await HookupProfile.exists({ user: req.user._id })) return res.status(409).json({ error: "You've already joined Hookup." });
  const b = req.body || {}, dob = new Date(b.birthDate);
  if (isNaN(dob.getTime())) return res.status(400).json({ error: "Enter your date of birth." });
  const age = ageOf(dob);
  if (age < 18 || (req.user.age && req.user.age < 18)) return res.status(403).json({ error: "Hookup is only for people aged 18 and over." });
  if (age > 100) return res.status(400).json({ error: "Enter a valid date of birth." });
  if (b.agree !== true) return res.status(400).json({ error: "Please confirm you are 18+ and accept the rules." });
  if (!GENDERS.includes(b.gender)) return res.status(400).json({ error: "Choose male or female." });
  const looking = [...new Set((b.lookingFor || []).filter(x => LOOKING.includes(x)))].slice(0, 4);
  if (!looking.length) return res.status(400).json({ error: "Choose what you're looking for." });
  const f = { bio: clean(b.bio).slice(0, 200), interests: clean(b.interests).slice(0, 100), area: clean(b.area).slice(0, 60) };
  if (blocked(`${f.bio} ${f.interests} ${f.area}`, true)) return res.status(400).json({ error: "Your profile has wording that isn't allowed on Hookup (links, contacts or prohibited terms)." });
  let hp;
  for (let i = 0; i < 6 && !hp; i++) {
    try {
      hp = await HookupProfile.create({
        user: req.user._id, alias: "HK-" + crypto.randomBytes(4).toString("hex").slice(0, 6).toUpperCase(),
        gender: b.gender, birthDate: dob, status: STATUSES.includes(b.status) ? b.status : "single", lookingFor: looking,
        interestedIn: INTERESTED.includes(b.interestedIn) ? b.interestedIn : "everyone", ...f, agreedAt: new Date()
      });
    } catch (e) { if (e.code !== 11000 || e.keyPattern?.user) throw e; }
  }
  if (!hp) return res.status(500).json({ error: "Could not create your ID. Try again." });
  hp.birthDate = dob;
  res.status(201).json({ profile: { ...card(hp), active: hp.active, showUsername: hp.showUsername } });
});

router.patch("/profile", auth, needProfile, async (req, res) => {
  const b = req.body || {}, hp = req.hp;
  if (b.status !== undefined && STATUSES.includes(b.status)) hp.status = b.status;
  if (b.interestedIn !== undefined && INTERESTED.includes(b.interestedIn)) hp.interestedIn = b.interestedIn;
  if (Array.isArray(b.lookingFor)) { const l = [...new Set(b.lookingFor.filter(x => LOOKING.includes(x)))].slice(0, 4); if (!l.length) return res.status(400).json({ error: "Choose what you're looking for." }); hp.lookingFor = l; }
  for (const [k, n] of [["bio", 200], ["interests", 100], ["area", 60]]) if (b[k] !== undefined) { const v = clean(b[k]).slice(0, n); if (blocked(v, true)) return res.status(400).json({ error: "That wording isn't allowed on Hookup." }); hp[k] = v; }
  if (typeof b.active === "boolean") hp.active = b.active;
  if (typeof b.showUsername === "boolean") hp.showUsername = b.showUsername;
  await hp.save();
  res.json({ profile: { ...card(hp), active: hp.active, showUsername: hp.showUsername } });
});

router.delete("/profile", auth, needProfile, async (req, res) => {
  const id = req.hp._id;
  await Promise.all([HookupPost.deleteMany({ author: id }), HookupMessage.deleteMany({ $or: [{ from: id }, { to: id }] }), HookupReveal.deleteMany({ $or: [{ from: id }, { to: id }] }), HookupBlock.deleteMany({ $or: [{ blocker: id }, { blocked: id }] })]);
  await HookupProfile.deleteOne({ _id: id });
  res.json({ ok: true });
});

/* ---------- people ---------- */
router.get("/people", auth, needProfile, async (req, res) => {
  const hp = req.hp, hidden = await hiddenIds(hp);
  const q = { active: true, flagged: false, _id: { $nin: [hp._id, ...hidden] }, interestedIn: { $in: ["everyone", hp.gender === "male" ? "men" : "women"] } };
  if (hp.interestedIn === "men") q.gender = "male"; else if (hp.interestedIn === "women") q.gender = "female";
  if (GENDERS.includes(req.query.gender)) q.gender = req.query.gender;
  if (LOOKING.includes(req.query.looking)) q.lookingFor = req.query.looking;
  if (clean(req.query.q)) q.alias = { $regex: rx(clean(req.query.q).toUpperCase()), $options: "i" };
  const rows = await HookupProfile.find(q).select("+birthDate").sort({ createdAt: -1 }).limit(60);
  res.json(await withNames(rows));
});

/* ---------- feed ---------- */
const shapePost = async (posts, hp) => {
  const authors = posts.map(p => p.author);
  const cards = await withNames(authors);
  return posts.map((p, i) => ({
    id: S(p._id), text: p.text, createdAt: p.createdAt, audience: p.audience, mine: S(authors[i]._id) === S(hp._id),
    likes: p.likes.length, likedByMe: p.likes.some(x => S(x) === S(hp._id)), author: cards[i]
  }));
};
router.get("/feed", auth, needProfile, async (req, res) => {
  const hp = req.hp, hidden = await hiddenIds(hp);
  const rows = await HookupPost.find({ author: { $nin: hidden }, $or: [{ audience: "all" }, { author: hp._id }, { audience: "selected", allowed: hp._id }] })
    .populate({ path: "author", select: "+birthDate alias gender status lookingFor user showUsername active flagged" }).sort({ createdAt: -1 }).limit(60);
  const ok = rows.filter(p => p.author && !p.author.flagged && (p.author.active || S(p.author._id) === S(hp._id)));
  res.json(await shapePost(ok, hp));
});

router.post("/posts", auth, needProfile, userLimit(3600000, 12), async (req, res) => {
  const text = clean(req.body?.text), hp = req.hp;
  if (!text || text.length > 300) return res.status(400).json({ error: "Posts must be 1–300 characters." });
  if (blocked(text, true)) return res.status(400).json({ error: "That wording isn't allowed on Hookup (no links, phone numbers or prohibited terms)." });
  let audience = "all", allowed = [];
  if (req.body?.audience === "selected") {
    const aliases = (Array.isArray(req.body.aliases) ? req.body.aliases : []).map(a => clean(a).toUpperCase()).filter(Boolean).slice(0, 20);
    const hidden = (await hiddenIds(hp)).map(S);
    allowed = (await HookupProfile.find({ alias: { $in: aliases }, _id: { $ne: hp._id } }).select("_id")).filter(p => !hidden.includes(S(p._id))).map(p => p._id);
    if (!allowed.length) return res.status(400).json({ error: "Add at least one valid ID to share with." });
    audience = "selected";
  }
  const p = await HookupPost.create({ author: hp._id, text, audience, allowed });
  res.status(201).json({ id: S(p._id) });
});
router.delete("/posts/:id", auth, needProfile, async (req, res) => {
  if (!isId(req.params.id)) return res.status(404).json({ error: "Not found." });
  const r = await HookupPost.deleteOne({ _id: req.params.id, author: req.hp._id });
  r.deletedCount ? res.json({ ok: true }) : res.status(404).json({ error: "Post not found." });
});
router.post("/posts/:id/like", auth, needProfile, async (req, res) => {
  if (!isId(req.params.id)) return res.status(404).json({ error: "Not found." });
  const p = await HookupPost.findById(req.params.id);
  if (!p || await isBlockedPair(req.hp._id, p.author)) return res.status(404).json({ error: "Post not found." });
  if (p.audience === "selected" && S(p.author) !== S(req.hp._id) && !p.allowed.some(x => S(x) === S(req.hp._id))) return res.status(403).json({ error: "Not available." });
  const i = p.likes.findIndex(x => S(x) === S(req.hp._id));
  if (i < 0) p.likes.push(req.hp._id); else p.likes.splice(i, 1);
  await p.save();
  res.json({ likes: p.likes.length, likedByMe: i < 0 });
});

/* ---------- chats (separate, incognito inbox) ---------- */
router.get("/chats", auth, needProfile, async (req, res) => {
  const hp = req.hp, me = S(hp._id), hidden = (await hiddenIds(hp)).map(S);
  const msgs = await HookupMessage.find({ $or: [{ from: hp._id }, { to: hp._id }] }).sort({ createdAt: -1 }).limit(400);
  const map = new Map();
  for (const m of msgs) {
    const other = S(m.from) === me ? S(m.to) : S(m.from);
    if (hidden.includes(other)) continue;
    if (!map.has(other)) map.set(other, { last: m, unread: 0 });
    if (S(m.to) === me && !m.readAt && m.kind === "text") map.get(other).unread++;
  }
  const profs = await HookupProfile.find({ _id: { $in: [...map.keys()] } }).select("+birthDate");
  const cards = await withNames(profs);
  const out = profs.map((p, i) => {
    const t = map.get(S(p._id)), kind = t.last.kind;
    return { ...cards[i], last: kind === "reveal" ? "Shared their profile" : kind === "hide" ? "Stopped sharing profile" : t.last.text.slice(0, 50), lastMine: S(t.last.from) === me, unread: t.unread, at: t.last.createdAt };
  }).sort((a, b) => new Date(b.at) - new Date(a.at));
  res.json(out);
});

router.get("/chats/:alias", auth, needProfile, async (req, res) => {
  const hp = req.hp, other = await byAlias(req.params.alias);
  if (!other) return res.status(404).json({ error: "That ID doesn't exist." });
  const blockedPair = await isBlockedPair(hp._id, other._id);
  const iBlocked = !!(await HookupBlock.exists({ blocker: hp._id, blocked: other._id }));
  if (blockedPair && !iBlocked) return res.status(403).json({ error: "You can't message this ID.", code: "blocked" });
  const rows = (await HookupMessage.find({ $or: [{ from: hp._id, to: other._id }, { from: other._id, to: hp._id }] }).sort({ createdAt: -1 }).limit(200)).reverse();
  await HookupMessage.updateMany({ from: other._id, to: hp._id, readAt: null }, { $set: { readAt: new Date() } });
  const [iShared, theirs] = await Promise.all([HookupReveal.exists({ from: hp._id, to: other._id }), HookupReveal.findOne({ from: other._id, to: hp._id })]);
  let theirShare = null;
  if (theirs) { const u = await User.findById(other.user).select("username displayName type"); if (u) theirShare = { userId: S(u._id), username: u.username, displayName: u.displayName || "" }; }
  const [c] = await withNames([other]);
  res.json({ with: c, iBlocked, iShared: !!iShared, theirShare, messages: rows.map(m => ({ id: S(m._id), mine: S(m.from) === S(hp._id), text: m.text, kind: m.kind, createdAt: m.createdAt, readAt: m.readAt || null })) });
});

router.post("/chats/:alias", auth, needProfile, userLimit(60000, 40), async (req, res) => {
  const text = clean(req.body?.text), hp = req.hp, other = await byAlias(req.params.alias);
  if (!other || other.flagged) return res.status(404).json({ error: "That ID doesn't exist." });
  if (S(other._id) === S(hp._id)) return res.status(400).json({ error: "You can't message yourself." });
  if (!text || text.length > 1000) return res.status(400).json({ error: "Message must be 1–1000 characters." });
  if (await HookupBlock.exists({ blocker: hp._id, blocked: other._id })) return res.status(403).json({ error: "Unblock this ID to message them." });
  if (await HookupBlock.exists({ blocker: other._id, blocked: hp._id })) return res.status(403).json({ error: "You can't message this ID." });
  if (blocked(text, false)) return res.status(400).json({ error: "That message contains wording that isn't allowed on Hookup." });
  const m = await HookupMessage.create({ from: hp._id, to: other._id, text });
  res.status(201).json({ id: S(m._id) });
});

// "Show my profile": share your real username with ONE person (they can then open your profile)
router.post("/chats/:alias/reveal", auth, needProfile, async (req, res) => {
  const hp = req.hp, other = await byAlias(req.params.alias);
  if (!other || S(other._id) === S(hp._id)) return res.status(404).json({ error: "That ID doesn't exist." });
  if (await isBlockedPair(hp._id, other._id)) return res.status(403).json({ error: "You can't do that with this ID." });
  const share = req.body?.share !== false;
  if (share) {
    await HookupReveal.updateOne({ from: hp._id, to: other._id }, {}, { upsert: true });
    await HookupMessage.create({ from: hp._id, to: other._id, text: "shared their profile", kind: "reveal" });
  } else {
    await HookupReveal.deleteOne({ from: hp._id, to: other._id });
    await HookupMessage.create({ from: hp._id, to: other._id, text: "stopped sharing their profile", kind: "hide" });
  }
  res.json({ iShared: share });
});

/* ---------- block / report ---------- */
router.post("/block/:alias", auth, needProfile, async (req, res) => {
  const other = await byAlias(req.params.alias);
  if (!other || S(other._id) === S(req.hp._id)) return res.status(404).json({ error: "That ID doesn't exist." });
  await HookupBlock.updateOne({ blocker: req.hp._id, blocked: other._id }, {}, { upsert: true });
  await HookupReveal.deleteMany({ $or: [{ from: req.hp._id, to: other._id }, { from: other._id, to: req.hp._id }] });
  res.json({ ok: true });
});
router.delete("/block/:alias", auth, needProfile, async (req, res) => {
  const other = await byAlias(req.params.alias);
  if (other) await HookupBlock.deleteOne({ blocker: req.hp._id, blocked: other._id });
  res.json({ ok: true });
});
router.get("/blocks", auth, needProfile, async (req, res) => {
  const ids = await HookupBlock.find({ blocker: req.hp._id }).distinct("blocked");
  res.json((await HookupProfile.find({ _id: { $in: ids } }).select("+birthDate")).map(card));
});
router.post("/report/:alias", auth, needProfile, userLimit(3600000, 20), async (req, res) => {
  const other = await byAlias(req.params.alias);
  if (!other || S(other._id) === S(req.hp._id)) return res.status(404).json({ error: "That ID doesn't exist." });
  const reason = REASONS.includes(req.body?.reason) ? req.body.reason : "other";
  await HookupReport.create({ reporter: req.hp._id, target: other._id, reason, text: clean(req.body?.text).slice(0, 200) });
  const distinct = (await HookupReport.find({ target: other._id }).distinct("reporter")).length;
  if (reason === "underage" || distinct >= 3) { other.flagged = true; await other.save(); }   // hidden until an admin reviews it
  await HookupBlock.updateOne({ blocker: req.hp._id, blocked: other._id }, {}, { upsert: true });
  res.json({ ok: true });
});

module.exports = router;