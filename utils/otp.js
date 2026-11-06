const crypto = require("crypto");
function makeOtp() { return String(crypto.randomInt(0, 1000000)).padStart(6, "0"); }
function hashOtp(code) { return crypto.createHash("sha256").update(`${code}:${process.env.JWT_SECRET}`).digest("hex"); }
module.exports = { makeOtp, hashOtp };
