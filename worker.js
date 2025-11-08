export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    const path = url.pathname;
    const params = url.searchParams;

    // 获取请求参数
    const uid = params.get("uid");
    const exp = Number(params.get("exp"));
    const sig = params.get("sig");

    // 设置重定向地址
    const EXPIRED_REDIRECT_URL = "https://pwbtw.com/id6024";
    const INVALID_LINK_URL = "https://life4u22.blogspot.com/p/ott-channel-review.html";

    // 检查参数
    if (!uid || !exp || !sig) {
      return Response.redirect(INVALID_LINK_URL, 302);
    }

    const now = Date.now();
    if (now > exp) {
      // 🔁 到期后跳转到指定网页
      return Response.redirect(EXPIRED_REDIRECT_URL, 302);
    }

    // 验证签名
    const text = `${uid}:${exp}`;
    const expectedSig = await sign(text, env.SIGN_SECRET_GLOBAL);
    if (expectedSig !== sig) {
      return Response.redirect(INVALID_LINK_URL, 302);
    }

    // 绑定 IP
    const ip = request.headers.get("CF-Connecting-IP") || "0.0.0.0";
    const key = `uid:${uid}`;
    const stored = await env.UID_BINDINGS.get(key);

    if (stored && stored !== ip) {
      return new Response("🚫 IP Mismatch - Unauthorized Access", { status: 403 });
    }

    if (!stored) {
      // 首次访问绑定 IP，保存 24 小时
      await env.UID_BINDINGS.put(key, ip, { expirationTtl: 86400 });
    }

    // 代理到 GitHub Pages
    const githubUrl = env.GITHUB_URL || "https://skyline5108.github.io/playlist";
    const targetUrl = githubUrl + path + url.search;
    return fetch(targetUrl, request);
  }
};

// 生成签名的函数
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
