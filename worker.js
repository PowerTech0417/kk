addEventListener("fetch", event => {
  event.respondWith(handleRequest(event.request));
});

async function handleRequest(request) {
  const url = new URL(request.url);
  const path = url.pathname;
  const params = url.searchParams;

  // === ⚙️ 配置区 ===
  const GITHUB_PAGES_URL = "https://skyline5108.github.io/playlist";
  const EXPIRED_REDIRECT_URL = "https://life4u22.blogspot.com/p/powertech.html"; // 过期跳转
  const IP_LOCK_URL = "https://life4u22.blogspot.com/p/id-ban.html"; // 设备冲突跳转
  const NON_OTT_REDIRECT_URL = "https://life4u22.blogspot.com/p/ott-channel-review.html"; // 🆕 非 OTT 打开跳转
  const SIGN_SECRET = "mySuperSecretKey"; // 用于签名验证
  const OTT_KEYWORDS = ["OTT Player", "OTT TV", "OTT Navigator"];
  // =================

  // ✅ 特殊路径：/test — 测试 KV 是否工作
  if (path === "/test") {
    try {
      await UID_BINDINGS.put("test-key", "hello-world");
      const val = await UID_BINDINGS.get("test-key");
      return new Response(`✅ KV 测试结果: ${val || "未读取到值"}`, {
        status: 200,
        headers: { "content-type": "text/plain; charset=utf-8" },
      });
    } catch (e) {
      return new Response(`❌ KV 测试失败: ${e.message}`, {
        status: 500,
        headers: { "content-type": "text/plain; charset=utf-8" },
      });
    }
  }

  // 1️⃣ 检查 User-Agent 是否 OTT 应用
  const ua = request.headers.get("User-Agent") || "";
  const isOTT = OTT_KEYWORDS.some(keyword => ua.includes(keyword));

  // 🆕 如果不是 OTT 应用 → 跳转到频道说明页
  if (!isOTT) return Response.redirect(NON_OTT_REDIRECT_URL, 302);

  // 2️⃣ 解析签名参数
  const uid = params.get("uid");
  const exp = Number(params.get("exp"));
  const sig = params.get("sig");
  if (!uid || !exp || !sig)
    return new Response("🚫 Invalid Link", { status: 403 });

  // 3️⃣ 过期检查
  const now = Date.now();
  if (now > exp) return Response.redirect(EXPIRED_REDIRECT_URL, 302);

  // 4️⃣ 验证签名
  const text = `${uid}:${exp}`;
  const expectedSig = await sign(text, SIGN_SECRET);
  if (expectedSig !== sig)
    return new Response("🚫 Invalid Signature", { status: 403 });

  // 5️⃣ 生成设备指纹（兼容不同 OTT App）
  const deviceFingerprint = await getDeviceFingerprint(ua, uid, SIGN_SECRET);

  // 6️⃣ 检查 KV 永久绑定（同一设备共用）
  const key = `uid:${uid}`;
  let storedFingerprint = null;

  try {
    storedFingerprint = await UID_BINDINGS.get(key);
  } catch (err) {
    return new Response("⚠️ KV 未绑定或读取失败，请检查配置。", { status: 500 });
  }

  if (storedFingerprint && storedFingerprint !== deviceFingerprint) {
    // 不同设备访问同一个 UID → 封锁
    return Response.redirect(IP_LOCK_URL, 302);
  }

  if (!storedFingerprint) {
    // ✅ 永久保存
    await UID_BINDINGS.put(key, deviceFingerprint);
  }

  // 7️⃣ 允许访问 GitHub Pages 内容
  const target = `${GITHUB_PAGES_URL}${path}${url.search}`;
  return fetch(target, request);
}

/**
 * 🔐 HMAC SHA256 签名函数
 */
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

/**
 * 📱 设备指纹提取（兼容 OTT App）
 */
async function getDeviceFingerprint(ua, uid, secret) {
  const baseUA = ua
    .replace(/OTT\s*(Player|TV|Navigator)/gi, "")
    .replace(/\s+/g, " ")
    .trim();

  const simplifiedUA = baseUA
    .match(/(Android [0-9.]+|Linux|SmartTV|AFTMM|AFTT|Tizen|Web0S|AppleTV|Build\/[A-Za-z0-9]+)/g)
    ?.join("_") || baseUA.slice(0, 60);

  const fingerprintText = `${uid}:${simplifiedUA}`;
  return await sign(fingerprintText, secret);
}
