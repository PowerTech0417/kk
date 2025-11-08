export default {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);

    // ✅ 你的 GitHub Pages 地址（静态内容源）
    const GITHUB_PAGES_URL = "https://skyline5108.github.io/playlist/";

    // 🚫 其它访问者要重定向去的地址
    const REDIRECT_URL = "https://life4u22.blogspot.com/p/ott-channel-review.html";

    // 读取 User-Agent
    const ua = request.headers.get("User-Agent") || "";

    // ✅ 判断是否是 OTT Player（根据 UA 关键字匹配）
    // 你可以替换为你的播放器标识，例如 "OTTPlayer", "OTT TV", "OTT Navigator" 等
    const ottKeywords = ["OTT Player", "OTT TV", "OTT Navigator"];
    const isOTT = ottKeywords.some(keyword => ua.includes(keyword));

    if (isOTT) {
      // 允许访问，转发到 GitHub Pages
      const target = `${GITHUB_PAGES_URL}${url.pathname}${url.search}`;
      const response = await fetch(target, {
        method: request.method,
        headers: request.headers,
      });
      return response;
    } else {
      // 非 OTT Player → 302 跳转到指定网站
      return Response.redirect(REDIRECT_URL, 302);
    }
  },
};
  async fetch(request, env) {
    const url = new URL(request.url);
    const path = url.pathname;
    const params = url.searchParams;
    const uid = params.get("uid");
    const exp = Number(params.get("exp"));
    const sig = params.get("sig");

    if (!uid || !exp || !sig) {
      return new Response("🚫 Invalid Link", { status: 403 });
    }

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

    const ip = request.headers.get("CF-Connecting-IP") || "0.0.0.0";
    const key = `uid:${uid}`;
    const stored = await env.UID_BINDINGS.get(key);

    if (stored && stored !== ip) {
      return new Response("🚫 IP Mismatch - Unauthorized Access", { status: 403 });
    }

    if (!stored) {
      // 绑定首次访问的 IP，保存 24 小时
      await env.UID_BINDINGS.put(key, ip, { expirationTtl: 86400 });
    }

    // 代理 GitHub Pages 内容
    const githubUrl = env.GITHUB_URL;
    const targetUrl = githubUrl + path;
    return fetch(targetUrl, request);
  }
};

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
