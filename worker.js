addEventListener("fetch", event => {
  event.respondWith(handleRequest(event.request, event));
});

async function handleRequest(request, event) {
  const url = new URL(request.url);
  const path = url.pathname;
  const params = url.searchParams;

  // ====== 配置区域 ======
  const GITHUB_PAGES_URL = "https://skyline5108.github.io/playlist";
  const REDIRECT_URL = "https://life4u22.blogspot.com/p/ott-channel-review.html";
  const ottKeywords = ["OTT Player", "OTT TV", "OTT Navigator"];
  const SIGN_SECRET = SIGN_SECRET_GLOBAL; // 全局变量
  // =====================

  // 1️⃣ 检查 UA
  const ua = request.headers.get("User-Agent") || "";
  const isOTT = ottKeywords.some(keyword => ua.includes(keyword));
  if (!isOTT) {
    return Response.redirect(REDIRECT_URL, 302);
  }

  // 2️⃣ 校验参数
  const uid = params.get("uid");
  const exp = Number(params.get("exp"));
  const sig = params.get("sig");
  if (!uid || !exp || !sig) {
    return new Response("🚫 Invalid Link (missing parameters)", { status: 403 });
  }

  // 3️⃣ 检查是否过期
  const now = Date.now();
  if (now > exp) {
    return new Response("⏰ Link Expired", { status: 403 });
  }

  // 4️⃣ 校验签名
  const text = `${uid}:${exp}`;
  const expectedSig = await sign(text, SIGN_SECRET);
  if (expectedSig !== sig) {
    return new Response("🚫 Invalid Signature", { status: 403 });
  }

  // 5️⃣ 绑定 UID 与 IP
  const ip = request.headers.get("CF-Connecting-IP") || "0.0.0.0";
  const key = `uid:${uid}`;
  const stored = await UID_BINDINGS.get(key);
  if (stored && stored !== ip) {
    return new Response("🚫 IP Mismatch - Unauthorized Access", { status: 403 });
  }
  if (!stored) {
    await UID_BINDINGS.put(key, ip, { expirationTtl: 86400 }); // 保存 24 小时
  }

  // 6️⃣ 转发到 GitHub Pages 内容
  const target = `${GITHUB_PAGES_URL}${path}${url.search}`;
  return fetch(target, request);
}

// 🔐 计算签名
async function sign(text, secret) {
  const key = await crypto.subtle.importKey(
    "raw",
    new TextEncoder().encode(secret),
