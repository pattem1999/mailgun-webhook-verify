// Test helper: signed x-www-form-urlencoded body. PowerShell: $env:MAILGUN_SIGNING_KEY="..." ; node scripts/local-sign.js
const crypto = require("crypto");

const key = process.env.MAILGUN_SIGNING_KEY;
if (!key) {
  console.error("Set MAILGUN_SIGNING_KEY in the environment.");
  process.exit(1);
}

const token = crypto.randomBytes(25).toString("hex");
const timestamp = String(Math.floor(Date.now() / 1000));
const signature = crypto
  .createHmac("sha256", key)
  .update(timestamp + token)
  .digest("hex");

const body = new URLSearchParams({ token, timestamp, signature, event: "delivered" }).toString();

console.log("--- Copy as raw POST body (x-www-form-urlencoded) ---");
console.log(body);
console.log("--- Example curl (bash) ---");
console.log(
  `curl -sS -X POST -H "Content-Type: application/x-www-form-urlencoded" --data '${body}' "YOUR_WORKER_URL"`
);
