export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    const path = url.pathname;
    const params = url.searchParams;

    // === ⚙️ 配置区 ===
    const GITHUB_PAGES_URL = "https://skyline5108.github.io/playlist";
    const REDIRECT_URL = "https://life4u22.blogspot.com/p/ott-channel-review.html";
    const EXPIRED_REDIRECT = "https://life4u22.blogspot.com/p/powertech.html";
    const IP_LOCK_REDIRECT = "https://life4u22.blogspot.com/p/id-ban.html";
    const SIGN_SECRET = "mySuperSecretKey"; // 你自己的密钥
    const OTT_KEYWORDS = ["OTT Player", "OTT TV", "OTT Navigator"];
    // ==================

    // 获取 User-Agent
    const ua = request.headers.get("User-Agent") || "";
    const isOTT = OTT_KEYWORDS.some(keyword => ua.toLowerCase().includes(keyword.toLowerCase()));
    if (!isOTT) {
      return Response.redirect(REDIRECT_URL, 302);
    }

    // 解析参数
    const uid = params.get("uid");
    const exp = Number(params.get("exp"));
    const sig = params.get("sig");
    if (!uid || !exp || !sig) {
      return new Response("🚫 Invalid Link", { status: 403 });
    }

    // 检查是否过期
    const now = Date.now();
    if (now > exp) {
      return Response.redirect(EXPIRED_REDIRECT, 302);
    }

    // 校验签名
    const text = `${uid}:${exp}`;
    const expectedSig = await sign(text, SIGN_SECRET);
    if (expectedSig !== sig) {
      return new Response("🚫 Invalid Signature", { status: 403 });
    }

    // 获取 IP 并验证锁定
    const ip = request.headers.get("CF-Connecting-IP") || "0.0.0.0";
    const key = `uid:${uid}`;
    const storedIP = await env.UID_BINDINGS.get(key);

    if (storedIP && storedIP !== ip) {
      // 已锁定其他 IP → 重定向
      return Response.redirect(IP_LOCK_REDIRECT, 302);
    }

    if (!storedIP) {
      // 首次访问 → 绑定 IP
      await env.UID_BINDINGS.put(key, ip, { expirationTtl: 86400 }); // 有效期 24 小时
    }

    // 转发请求到 GitHub Pages
    const target = `${GITHUB_PAGES_URL}${path}${url.search}`;
    return fetch(target, request);
  },
};

// 签名函数
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
