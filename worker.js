addEventListener("fetch", event => {
  event.respondWith(handleRequest(event.request, event));
});

async function handleRequest(request, event) {
  const url = new URL(request.url);
  const path = url.pathname;
  const params = url.searchParams;

  // === ⚙️ 配置区 ===
  const GITHUB_PAGES_URL = "https://skyline5108.github.io/playlist";
  const REDIRECT_URL = "https://life4u22.blogspot.com/p/ott-channel-review.html";
  const EXPIRE_REDIRECT_URL = "https://life4u22.blogspot.com/p/powertech.html"; // ✅ 新增：过期跳转页
  const SIGN_SECRET = "mySuperSecretKey"; // ⚠️ 请修改为你自己的随机密钥
  const OTT_KEYWORDS = ["OTT Player", "OTT TV", "OTT Navigator"];
  // =================

  // 1️⃣ 检查 User-Agent
  const ua = request.headers.get("User-Agent") || "";
  const isOTT = OTT_KEYWORDS.some(keyword => ua.includes(keyword));
  if (!isOTT) {
    return Response.redirect(REDIRECT_URL, 302);
  }

  // 2️⃣ 解析参数
  const uid = params.get("uid");
  const exp = Number(params.get("exp"));
  const sig = params.get("sig");
  if (!uid || !exp || !sig) {
    return new Response("🚫 Invalid Link", { status: 403 });
  }

  // 3️⃣ 检查是否过期
  const now = Date.now();
  if (now > exp) {
    // ✅ 改为过期后重定向
    return Response.redirect(EXPIRE_REDIRECT_URL, 302);
  }

  // 4️⃣ 校验签名
  const text = `${uid}:${exp}`;
  const expectedSig = await sign(text, SIGN_SECRET);
  if (expectedSig !== sig) {
    return new Response("🚫 Invalid Signature", { status: 403 });
  }

  // 5️⃣ 绑定 IP（KV 存储）
  const ip = request.headers.get("CF-Connecting-IP") || "0.0.0.0";
  const key = `uid:${uid}`;
  const stored = await UID_BINDINGS.get(key);
  if (stored && stored !== ip) {
    return new Response("🚫 IP Mismatch - Unauthorized Access", { status: 403 });
  }
  if (!stored) {
    await UID_BINDINGS.put(key, ip, { expirationTtl: 86400 }); // 保存 24 小时
  }

  // 6️⃣ 转发内容到 GitHub Pages
  const target = `${GITHUB_PAGES_URL}${path}${url.search}`;
  return fetch(target, request);
}

// 🔐 HMAC 签名函数
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
