export default {
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
