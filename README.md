# Bara Cee backend

Node.js + Express + MongoDB API for the supplied Bara Cee frontend.

## 1. Requirements
- Node.js 20+
- MongoDB Atlas database
- Brevo account with a verified sender
- Render web service (or local Node host)

## 2. Install and configure
```bash
npm install
cp .env.example .env
```
Fill in `MONGODB_URI`, a long random `JWT_SECRET`, Brevo API key, and the exact verified sender email/name. Never commit `.env`.

## 3. Run locally
```bash
npm run dev
```
The API listens on `http://localhost:5000`; health check: `/health`.

## 4. Render
- Build command: `npm install`
- Start command: `npm start`
- Add every required `.env.example` variable in Render > Environment.
- Set `CLIENT_ORIGIN` to the exact deployed frontend origin.
- Do not set a fixed port; Render supplies `PORT`.
- Deploy and test `/health`.

## 5. Frontend signup change required (OTP)
The uploaded `app.js` currently calls `/auth/signup` and then displays “click the link”. Change that last step to show an OTP form and call:
- `POST /api/auth/verify-email` with `{ email, code }`
- `POST /api/auth/resend-code` with `{ email }`
Then show the login form. The backend does not send verification links; it sends a six-digit code.

Login remains `POST /api/auth/login` with `{ username, password }`. Store returned `token` as `bc_token`. `/api/me` returns the current user.

## 6. Manual business verification
After you have physically checked the business, get the MongoDB user `_id` from your admin database view and run:
```bash
curl -X POST "https://YOUR-API.onrender.com/api/admin/verify-business/USER_ID" ^
  -H "x-admin-key: YOUR_ADMIN_VERIFY_KEY"
```
Use PowerShell syntax if running on Windows:
```powershell
Invoke-RestMethod -Method Post `
  -Uri "https://YOUR-API.onrender.com/api/admin/verify-business/USER_ID" `
  -Headers @{ "x-admin-key" = "YOUR_ADMIN_VERIFY_KEY" }
```
Keep `ADMIN_VERIFY_KEY` private. Never put it in frontend JavaScript.

## 7. Listing expiry
Listings are visible for 30 hours. They remain renewable for another 3 days, then MongoDB TTL cleanup permanently deletes them. MongoDB TTL deletion is asynchronous and may happen after the expiry time, not at the exact second.

## 8. Important production notes
- Passwords are hashed with bcrypt (12 rounds); plaintext passwords are never stored.
- OTPs are hashed in MongoDB, expire after 10 minutes, and are limited to five attempts.
- Add CAPTCHA, email resend throttling, audit logs, moderation/report/block tools, backups, and monitoring before public launch.
- The current uploads folder is a development fallback. Render local disk is ephemeral and not a reliable permanent media store. Configure Cloudinary/S3 and replace disk uploads before real users upload photos/videos.
- The PayHero `/pay` route intentionally returns 503. Do not charge users until your real PayHero credentials, current endpoint contract, callback signature verification, idempotency, and refund/reconciliation process are implemented and tested.
- The online flag is a basic heartbeat. A scheduled stale-user cleanup or Redis presence service is needed for reliable presence across multiple instances.
- This is a functional starter backend, not a security audit or a complete production social network. Add automated tests and review privacy/terms/child-safety requirements before launch.
