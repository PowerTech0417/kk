export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    const path = url.pathname;
    const params = url.searchParams;

    // === ⚙️ 配置区 ===
    const GITHUB_PAGES_URL = "https://skyline5108.github.io/playlist";
    const REDIRECT_URL = "https://life4u22.blogspot.com/p/ott-channel-review.html"; // 非 OTT 访问
    const EXPIRED_REDIRECT = "https://life4u22.blogspot.com/p/powertech.html"; // 过期跳转
    const IP_LOCK_REDIRECT = "https://life4u22.blogspot.com/p/id-ban.html"; // IP/设备锁
    const SIGN_SECRET = "mySuperSecretKey"; // 你设置的密钥
    const OTT_KEYWORDS = ["OTT TV", "OTT Player", "OTT Navigator"]; // ✅ 仅允许这些播放器
    // ==================

    const ua = request.headers.get("User-Agent") || "";
    const ip = request.headers.get("CF-Connecting-IP") || "0.0.0.0";
    const uid = params.get("uid");
    const exp = Number(params.get("exp"));
    const sig = params.get("sig");

    // 1️⃣ 检查 User-Agent 是否允许
    const isOTT = OTT_KEYWORDS.some(k => ua.includes(k));
    if (!isOTT) {
      return Response.redirect(REDIRECT_URL, 302);
    }

    // 2️⃣ 检查参数完整性
    if (!uid || !exp || !sig) {
      return new Response("🚫 Invalid Link", { status: 403 });
    }

    // 3️⃣ 检查是否过期
    if (Date.now() > exp) {
      return Response.redirect(EXPIRED_REDIRECT, 302);
    }

    // 4️⃣ 校验签名
    const text = `${uid}:${exp}`;
    const expectedSig = await sign(text, SIGN_SECRET);
    if (expectedSig !== sig) {
      return new Response("🚫 Invalid Signature", { status: 403 });
    }

    // 5️⃣ 生成唯一指纹（防止同Wi-Fi多设备共享）
    const fingerprint = await sha256(`${ip}|${ua}`);

    // 6️⃣ KV 存储验证
    const key = `uid:${uid}`;
    const storedFingerprint = await env.UID_BINDINGS.get(key);

    if (storedFingerprint && storedFingerprint !== fingerprint) {
      // ⚠️ 其他设备尝试访问（即使同 Wi-Fi）
      return Response.redirect(IP_LOCK_REDIRECT, 302);
    }

    // 7️⃣ 第一次访问则绑定指纹
    if (!storedFingerprint) {
      await env.UID_BINDINGS.put(key, fingerprint, { expirationTtl: 86400 }); // 24 小时有效
    }

    // 8️⃣ 转发至 GitHub Pages 内容
    const target = `${GITHUB_PAGES_URL}${path}${url.search}`;
    return fetch(target, request);
  },
};

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

// 🔒 生成 SHA256 指纹
async function sha256(str) {
  const buf = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(str));
  return Array.from(new Uint8Array(buf))
    .map(b => b.toString(16).padStart(2, "0"))
    .join("");
}
