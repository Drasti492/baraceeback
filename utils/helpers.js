const axios = require("axios");
const Notification = require("../models/Notification");

const clean = s => String(s || "").trim();
const rx = s => String(s).replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
const isId = id => /^[a-f0-9]{24}$/i.test(String(id));
const S = x => String(x);

const publicUser = u => ({
  id: S(u._id), username: u.username, displayName: u.displayName || "", type: u.type,
  bizName: u.bizName, verified: !!u.verified, avatar: u.avatar,
  online: !!u.online && u.showOnlineStatus !== false
});

const emit = (req, userId, event, payload) => {
  const io = req.app.get("io");
  if (io) io.to(`user:${userId}`).emit(event, payload);
};

async function notify(req, { recipient, actor, type, body, post, messageRef, story }) {
  if (!recipient || (actor && S(recipient) === S(actor))) return;
  try {
    if (type === "message") await Notification.deleteMany({ recipient, actor, type, readAt: null });
    if ((type === "like" || type === "follow") && await Notification.exists({ recipient, actor, type, post, readAt: null })) return;
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

module.exports = { clean, rx, isId, S, publicUser, emit, notify, sendCode };