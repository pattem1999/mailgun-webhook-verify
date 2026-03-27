const MAX_TIMESTAMP_SKEW_SEC = 900;

export default {
  async fetch(request, env) {

    // ✅ Health check
    if (request.method === "GET") {
      return new Response(JSON.stringify({
        ok: true,
        message: "Mailgun webhook verification service running"
      }), {
        headers: { "content-type": "application/json" }
      });
    }

    if (request.method !== "POST") {
      return new Response("Method Not Allowed", { status: 405 });
    }

    const signingKey = env.MAILGUN_SIGNING_KEY;

    if (!signingKey) {
      return new Response("Missing MAILGUN_SIGNING_KEY", { status: 500 });
    }

    const contentType = (request.headers.get("content-type") || "").toLowerCase();
    const raw = await request.text();

    let token, timestamp, signature;

    // ✅ Handle form data (Mailgun default)
    if (contentType.includes("application/x-www-form-urlencoded")) {
      const params = new URLSearchParams(raw);
      token = params.get("token");
      timestamp = params.get("timestamp");
      signature = params.get("signature");
    } 
    // ✅ Handle JSON (optional)
    else if (contentType.includes("application/json")) {
      try {
        const body = JSON.parse(raw);
        token = body.token;
        timestamp = body.timestamp;
        signature = body.signature;
      } catch {
        return new Response("Invalid JSON", { status: 400 });
      }
    } else {
      return new Response("Unsupported Content-Type", { status: 415 });
    }

    if (!token || !timestamp || !signature) {
      return new Response(JSON.stringify({
        error: "missing_fields"
      }), { status: 400 });
    }

    // ✅ Timestamp validation
    const now = Math.floor(Date.now() / 1000);
    if (Math.abs(now - timestamp) > MAX_TIMESTAMP_SKEW_SEC) {
      return new Response("Timestamp expired", { status: 403 });
    }

    // ✅ Signature verification
    const expected = await hmacSha256Hex(signingKey, timestamp + token);

    if (!timingSafeEqual(expected, signature)) {
      return new Response("Invalid signature", { status: 403 });
    }

    // ✅ SUCCESS
    return new Response(JSON.stringify({
      verified: true,
      message: "Webhook verified successfully"
    }), {
      headers: { "content-type": "application/json" }
    });
  }
};

// 🔐 HMAC generator
async function hmacSha256Hex(secret, message) {
  const enc = new TextEncoder();
  const key = await crypto.subtle.importKey(
    "raw",
    enc.encode(secret),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"]
  );
  const sig = await crypto.subtle.sign("HMAC", key, enc.encode(message));
  return [...new Uint8Array(sig)]
    .map(b => b.toString(16).padStart(2, "0"))
    .join("");
}

// 🔐 Timing safe compare
function timingSafeEqual(a, b) {
  if (a.length !== b.length) return false;
  let result = 0;
  for (let i = 0; i < a.length; i++) {
    result |= a.charCodeAt(i) ^ b.charCodeAt(i);
  }
  return result === 0;
}