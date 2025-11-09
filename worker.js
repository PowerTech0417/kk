addEventListener("fetch", event => {
  event.respondWith(handleRequest(event.request, event));
});

async function handleRequest(request, event) {
  const url = new URL(request.url);
  const path = url.pathname;
  const params = url.searchParams;

  // === ⚙️ 配置区 ===
  const GITHUB_PAGES_URL = "https://skyline5108.github.io/playlist";
  const REDIRECT_URL = "https://life4u22.blogspot.com/p/powertech.html"; // 过期
  const IP_LOCK_URL = "https://life4u22.blogspot.com/p/id-ban.html"; // 设备冲突
  const SIGN_SECRET = "mySuperSecretKey";
  const OTT_KEYWORDS = ["OTT Player", "OTT TV", "OTT Navigator"];
  // =================

  // 1️⃣ 检查 User-Agent
  const ua = request.headers.get("User-Agent") || "";
  const isOTT = OTT_KEYWORDS.some(keyword => ua.includes(keyword));
  if (!isOTT) return Response.redirect(REDIRECT_URL, 302);

  // 2️⃣ 解析参数
  const uid = params.get("uid");
  const exp = Number(params.get("exp"));
  const sig = params.get("sig");
  if (!uid || !exp || !sig)
    return new Response("🚫 Invalid Link", { status: 403 });

  // 3️⃣ 检查是否过期
  const now = Date.now();
  if (now > exp) return Response.redirect(REDIRECT_URL, 302);

  // 4️⃣ 校验签名
  const text = `${uid}:${exp}`;
  const expectedSig = await sign(text, SIGN_SECRET);
  if (expectedSig !== sig)
    return new Response("🚫 Invalid Signature", { status: 403 });

  // 5️⃣ 提取 UA 中的设备信息（排除 app 名）
  const cleanedUA = ua
    .replace(/OTT\s*(Player|TV|Navigator)/gi, "")
    .trim();

  // 6️⃣ 生成设备指纹（UID + cleaned UA）
  const deviceFingerprint = await sign(`${uid}:${cleanedUA}`, SIGN_SECRET);
  const key = `uid:${uid}`;
  const stored = await UID_BINDINGS.get(key);

  // 7️⃣ 检查是否为同一设备
  if (stored && stored !== deviceFingerprint) {
    return Response.redirect(IP_LOCK_URL, 302);
  }

  // 8️⃣ 保存绑定（同设备可跨 app / 网络使用）
  if (!stored) {
    await UID_BINDINGS.put(key, deviceFingerprint, { expirationTtl: 86400 });
  }

  // 9️⃣ 代理到 GitHub Pages
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
