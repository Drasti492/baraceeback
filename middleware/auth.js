const jwt = require("jsonwebtoken");
const User = require("../models/User");

async function auth(req, res, next) {
  try {
    const token = (req.headers.authorization || "")
      .replace(/^Bearer\s+/i, "");

    if (!token) {
      return res.status(401).json({ error: "Please log in." });
    }

    const payload = jwt.verify(token, process.env.JWT_SECRET);

    const user = await User.findById(payload.sub);

    if (!user || !user.emailVerified) {
      return res.status(401).json({
        error: "Account not found or email not verified."
      });
    }

    if (user.isDeactivated) {
      return res.status(403).json({
        error: "This account is deactivated. Reactivate it to continue."
      });
    }

    req.user = user;
    next();
  } catch (error) {
    return res.status(401).json({
      error: "Your session has expired. Please log in again."
    });
  }
}

module.exports = auth;