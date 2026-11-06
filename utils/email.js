const axios = require("axios");
async function sendVerificationEmail(email, code) {
  if (!process.env.BREVO_API_KEY || !process.env.BREVO_SENDER_EMAIL) {
    throw new Error("Brevo is not configured. Add BREVO_API_KEY and BREVO_SENDER_EMAIL in Render.");
  }
  const safeCode = String(code).replace(/[&<>"]/g, "");
  const response = await axios.post("https://api.brevo.com/v3/smtp/email", {
    sender: { name: process.env.BREVO_SENDER_NAME || "Bara Cee", email: process.env.BREVO_SENDER_EMAIL },
    to: [{ email }],
    subject: "Your Bara Cee verification code",
    htmlContent: `<div style="font-family:Arial,sans-serif;max-width:520px;margin:auto;padding:28px;color:#1b2033"><h2>Welcome to Bara Cee</h2><p>Use this code to verify your email address:</p><div style="font-size:34px;font-weight:700;letter-spacing:9px;padding:18px;background:#f3f5fa;text-align:center;border-radius:12px">${safeCode}</div><p>This code expires in 10 minutes. If you did not create this account, you can ignore this email.</p><p>— Bara Cee team</p></div>`
  }, { headers: { "api-key": process.env.BREVO_API_KEY, "Content-Type": "application/json", Accept: "application/json" }, timeout: 15000 });
  return response.data;
}
module.exports = { sendVerificationEmail };
