addEventListener("fetch", event => {
  event.respondWith(handleRequest(event.request, event));
});

async function handleRequest(request, event) {
  // ⚙️ 配置
  const GITHUB_PAGES_URL = "https://skyline5108.github.io/playlist";
  const REDIRECT_URL = "https://life4u22.blogspot.com/p/ott-channel-review.html";
  const SIGN_SECRET = "mySuperSecretKey";
  const OTT_KEYWORDS = ["OTT Player", "OTT TV", "OTT Navigator"];

  const url = new URL(request.url);
  const ua = request.headers.get("User-Agent") || "";
  const isOTT = OTT_KEYWORDS.some(k => ua.includes(k));

  if (!isOTT) return Response.redirect(REDIRECT_URL, 302);

  const uid = url.searchParams.get("uid");
  const exp = Number(url.searchParams.get("exp"));
  const sig = url.searchParams.get("sig");
  if (!uid || !exp || !sig) return new Response("🚫 Invalid Link", { status: 403 });

  const now = Date.now();
  if (now > exp) return new Response("⏰ Link Expired", { status: 403 });

  const expectedSig = await sign(`${uid}:${exp}`, SIGN_SECRET);
  if (sig !== expectedSig) return new Response("🚫 Invalid Signature", { status: 403 });

  const ip = request.headers.get("CF-Connecting-IP") || "0.0.0.0";
  const key = `uid:${uid}`;
  const stored = await UID_BINDINGS.get(key);
  if (stored && stored !== ip) return new Response("🚫 IP Mismatch", { status: 403 });
  if (!stored) await UID_BINDINGS.put(key, ip, { expirationTtl: 86400 });

  const target = `${GITHUB_PAGES_URL}${url.pathname}${url.search}`;
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
  return Array.from(new Uint8Array(signature))
    .map(b => b.toString(16).padStart(2, "0"))
    .join("");
}
