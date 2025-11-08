addEventListener("fetch", event => {
  event.respondWith(handleRequest(event.request, env));
});

async function handleRequest(request, env) {
  const url = new URL(request.url);
  const path = url.pathname;
  const params = url.searchParams;

  const GITHUB_PAGES_URL = "https://skyline5108.github.io/playlist";
  const REDIRECT_URL = "https://life4u22.blogspot.com/p/ott-channel-review.html";
  const ottKeywords = ["OTT Player", "OTT TV", "OTT Navigator"];

  const ua = request.headers.get("User-Agent") || "";
  const isOTT = ottKeywords.some(keyword => ua.includes(keyword));
  if (!isOTT) return Response.redirect(REDIRECT_URL, 302);

  const uid = params.get("uid");
  const exp = Number(params.get("exp"));
  const sig = params.get("sig");
  if (!uid || !exp || !sig) return new Response("🚫 Invalid Link", { status: 403 });

  const now = Date.now();
  if (now > exp) return new Response("⏰ Link Expired", { status: 403 });

  const text = `${uid}:${exp}`;
  const expectedSig = await sign(text, env.SIGN_SECRET);
  if (expectedSig !== sig) return new Response("🚫 Invalid Signature", { status: 403 });

  const ip = request.headers.get("CF-Connecting-IP") || "0.0.0.0";
  const key = `uid:${uid}`;
  const stored = await env.UID_BINDINGS.get(key);
  if (stored && stored !== ip) return new Response("🚫 IP Mismatch", { status: 403 });
  if (!stored) await env.UID_BINDINGS.put(key, ip, { expirationTtl: 86400 });

  const target = `${GITHUB_PAGES_URL}${path}${url.search}`;
  return fetch(target, request);
}

async function sign(text, secret) {
  const key = await crypto.subtle.importKey(
    "raw",
    new TextEncoder().encode(secret),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"]
  );
  const signature = await crypto.subtle.sign("HMAC", key, new TextEncoder().encode(text));
  return Array.from(new Uint8Array(signature)).map(b => b.toString(16).padStart(2, "0")).join("");
}
