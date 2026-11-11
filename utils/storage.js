// Saves an uploaded file (multer memory buffer). Uses Cloudinary when configured (permanent),
// otherwise falls back to the local uploads folder (lost on every Render redeploy).
const path = require("path");
const fs = require("fs");
const crypto = require("crypto");

let cloud = null;
if (process.env.CLOUDINARY_CLOUD_NAME && process.env.CLOUDINARY_API_KEY && process.env.CLOUDINARY_API_SECRET) {
  cloud = require("cloudinary").v2;
  cloud.config({
    cloud_name: process.env.CLOUDINARY_CLOUD_NAME,
    api_key: process.env.CLOUDINARY_API_KEY,
    api_secret: process.env.CLOUDINARY_API_SECRET,
    secure: true
  });
}
const EXT = { "image/jpeg": ".jpg", "image/png": ".png", "image/webp": ".webp", "image/gif": ".gif", "video/mp4": ".mp4", "video/webm": ".webm", "video/quicktime": ".mov" };
const dir = path.join(__dirname, "..", "uploads");

async function saveFile(file) {
  if (cloud) {
    return new Promise((resolve, reject) => {
      cloud.uploader.upload_stream(
        { resource_type: file.mimetype.startsWith("video") ? "video" : "image", folder: "baracee" },
        (err, r) => (err ? reject(err) : resolve(r.secure_url))
      ).end(file.buffer);
    });
  }
  fs.mkdirSync(dir, { recursive: true });
  const name = `${Date.now()}-${crypto.randomBytes(8).toString("hex")}${EXT[file.mimetype] || ""}`;
  await fs.promises.writeFile(path.join(dir, name), file.buffer);
  return `/uploads/${name}`;
}
module.exports = { saveFile };