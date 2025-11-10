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
  const DEVICE_CONFLICT_URL = "https://life4u22.blogspot.com/p/id-ban.html"; // 封锁跳转
  const NON_OTT_REDIRECT_URL = "https://life4u22.blogspot.com/p/ott-channel-review.html"; // 非 OTT 打开跳转
  const SIGN_SECRET = "mySuperSecretKey"; // 签名密钥（请换成你的密钥）
  const OTT_KEYWORDS = ["OTT Player", "OTT TV", "OTT Navigator"]; // 允许的应用识别关键字
  const MAX_APPS_PER_DEVICE = 3; // 同一设备最多允许绑定多少个不同 OTT APP
  // =================

  // ✅ 测试路径：/test 检查 KV 写读与马来西亚时间
  if (path === "/test") {
    const malaysiaNow = new Date(Date.now() + 8 * 60 * 60 * 1000);
    const formattedMY = malaysiaNow.toISOString().replace("T", " ").slice(0, 19);
    try {
      await UID_BINDINGS.put("test-key", "hello-world");
      const val = await UID_BINDINGS.get("test-key");
      return new Response(
        `✅ KV 测试结果: ${val || "未读取到值"}\n🕒 当前马来西亚时间: ${formattedMY}`,
        { status: 200, headers: { "content-type": "text/plain; charset=utf-8" } }
      );
    } catch (e) {
      return new Response(
        `❌ KV 测试失败: ${e.message}\n🕒 马来西亚时间: ${formattedMY}`,
        { status: 500, headers: { "content-type": "text/plain; charset=utf-8" } }
      );
    }
  }

  // 1️⃣ 检查 UA：必须是 Android && 必须包含允许的 OTT 关键字
  const ua = request.headers.get("User-Agent") || "";
  const isAndroid = ua.includes("Android");
  const appType = OTT_KEYWORDS.find(k => ua.includes(k)) || null;
  if (!isAndroid || !appType) {
    return Response.redirect(NON_OTT_REDIRECT_URL, 302);
  }

  // 2️⃣ 解析签名参数
  const uid = params.get("uid");
  const exp = Number(params.get("exp"));
  const sig = params.get("sig");
  if (!uid || !exp || !sig) return new Response("🚫 Invalid Link", { status: 403 });

  // 🇲🇾 当前马来西亚时间（UTC+8）
  const malaysiaNow = new Date(Date.now() + 8 * 60 * 60 * 1000);
  const nowMillis = malaysiaNow.getTime();

  // 3️⃣ 过期检查
  if (nowMillis > exp) return Response.redirect(EXPIRED_REDIRECT_URL, 302);

  // 4️⃣ 验证签名
  const text = `${uid}:${exp}`;
  const expectedSig = await sign(text, SIGN_SECRET);
  if (expectedSig !== sig) return new Response("🚫 Invalid Signature", { status: 403 });

  // 5️⃣ 生成设备指纹（UID + IP + 简化 UA）
  const ip = request.headers.get("CF-Connecting-IP") || "0.0.0.0";
  const deviceFingerprint = await getDeviceFingerprint(ua, ip, uid, SIGN_SECRET);

  // 6️⃣ 读取 KV（结构说明：存储 JSON 对象，形如： { device: "<fingerprint>", apps: ["OTT Player","OTT TV"] } ）
  const key = `uid:${uid}`;
  let stored = null;
  try {
    const raw = await UID_BINDINGS.get(key);
    if (raw) stored = JSON.parse(raw);
  } catch (e) {
    return new Response("⚠️ KV 读取失败，请检查配置。", { status: 500 });
  }

  // 7️⃣ 规则实现
  // 情形 A：未绑定（首次登入） => 绑定 device + apps = [appType]
  if (!stored) {
    const toStore = { device: deviceFingerprint, apps: [appType] };
    try {
      await UID_BINDINGS.put(key, JSON.stringify(toStore));
      console.log(`UID ${uid} 首次绑定 device, app=${appType}`);
    } catch (e) {
      return new Response("⚠️ KV 写入失败，请检查配置。", { status: 500 });
    }
    // 允许访问（首次绑定后直接转发）
    const target = `${GITHUB_PAGES_URL}${path}${url.search}`;
    return fetch(target, request);
  }

  // 情形 B：已有绑定
  const sameDevice = stored.device === deviceFingerprint;
  if (!sameDevice) {
    // 不同设备 -> 直接封锁（重定向）
    return Response.redirect(DEVICE_CONFLICT_URL, 302);
  }

  // 同设备：检查当前 app 是否已在绑定列表中
  const apps = Array.isArray(stored.apps) ? stored.apps : [];
  if (apps.includes(appType)) {
    // 已绑定该 App -> 允许访问
    const target = `${GITHUB_PAGES_URL}${path}${url.search}`;
    return fetch(target, request);
  }

  // 同设备但该 App 尚未绑定
  if (apps.length < MAX_APPS_PER_DEVICE) {
    // 可新增绑定：push 并写回 KV
    apps.push(appType);
    stored.apps = apps;
    try {
      await UID_BINDINGS.put(key, JSON.stringify(stored));
      console.log(`UID ${uid} 在同设备新增绑定 app=${appType} (now ${apps.length}/${MAX_APPS_PER_DEVICE})`);
    } catch (e) {
      return new Response("⚠️ KV 写入失败，请检查配置。", { status: 500 });
    }
    const target = `${GITHUB_PAGES_URL}${path}${url.search}`;
    return fetch(target, request);
  }

  // 超过配额 -> 封锁
  return Response.redirect(DEVICE_CONFLICT_URL, 302);
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
 * 📱 设备指纹（UID + IP + 简化 UA）
 */
async function getDeviceFingerprint(ua, ip, uid, secret) {
  const cleanUA = ua.replace(/\s+/g, " ").trim().slice(0, 120);
  const base = `${uid}:${ip}:${cleanUA}`;
  return await sign(base, secret);
}
