export default {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);
    const path = url.pathname;
    const params = url.searchParams;

    // ====== 配置区域 ======
    const GITHUB_PAGES_URL = "https://skyline5108.github.io/playlist"; // ✅ 改成你的 GitHub Pages 地址
    const REDIRECT_URL = "https://life4u22.blogspot.com/p/ott-channel-review.html"; // 🚫 非 OTT 重定向
    const ottKeywords = ["OTT Player", "OTT TV", "OTT Navigator"]; // ✅ 允许 UA
    // =====================

    // 检查 UA
    const ua = request.headers.get("User-Agent") || "";
    const isOTT = ottKeywords.some(keyword => ua.includes(keyword));

    // 如果不是 OTT Player，则重定向
    if (!isOTT) {
      return Response.redirect(REDIRECT_URL, 302);
    }

    // 检查授权参数
    const uid = params.get("uid");
    const exp = Number(params.get("exp"));
    const sig = params.get("sig");

    if (!uid || !exp || !sig) {
      return new Response("🚫 Invalid Link (missing parameters)", { status: 403 });
    }

    // 检查过期
    const now = Date.now();
    if (now > exp) {
      return new Response("⏰ Link Expired", { status: 403 });
    }

    // 验证签名
    const text = `${uid}:${exp}`;
    const expectedSig = await sign(text, env.SIGN_SECRET);
    if (expectedSig !== sig) {
      return new Response("🚫 Invalid Signature", { status: 403 });
    }

    // 绑定 UID 与 IP
    const ip = request.headers.get("CF-Connecting-IP") || "0.0.0.0";
    const key = `uid:${uid}`;
    const stored = await env.UID_BINDINGS.get(key);

    if (stored && stored !== ip) {
      return new Response("🚫 IP Mismatch - Unauthorized Access", { status: 403 });
    }

    if (!stored) {
      await env.UID_BINDINGS.put(key, ip, { expirationTtl: 86400 }); // 绑定 24 小时
    }

    // 代理 GitHub Pages 内容
    const target = `${GITHUB_PAGES_URL}${path}${url.search}`;
    const response = await fetch(target, {
      method: request.method,
      headers: request.headers,
    });
    return response;
  }
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
