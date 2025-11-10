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
  const DEVICE_CONFLICT_URL = "https://life4u22.blogspot.com/p/id-ban.html"; // 其他设备登入跳转
  const NON_OTT_REDIRECT_URL = "https://life4u22.blogspot.com/p/ott-channel-review.html"; // 非 OTT 打开跳转
  const SIGN_SECRET = "mySuperSecretKey"; // 签名密钥
  const OTT_KEYWORDS = ["OTT Player", "OTT TV", "OTT Navigator"]; // 允许的应用
  const MAX_APP_PER_DEVICE = 3; // ✅ 同一设备最多绑定 3 个 OTT 应用
  // =================

  // ✅ 测试路径
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

  // 1️⃣ 检查 User-Agent 是否 OTT 应用 + Android 平台
  const ua = request.headers.get("User-Agent") || "";
  const isAndroid = ua.includes("Android");
  const isOTT = OTT_KEYWORDS.some(keyword => ua.includes(keyword));
  if (!isAndroid || !isOTT) {
    return Response.redirect(NON_OTT_REDIRECT_URL, 302);
  }

  // 2️⃣ 解析签名参数
  const uid = params.get("uid");
  const exp = Number(params.get("exp"));
  const sig = params.get("sig");
  if (!uid || !exp || !sig)
    return new Response("🚫 Invalid Link", { status: 403 });

  // 🇲🇾 当前马来西亚时间（UTC+8）
  const malaysiaNow = new Date(Date.now() + 8 * 60 * 60 * 1000);
  const nowMillis = malaysiaNow.getTime();

  // 3️⃣ 过期检查
  if (nowMillis > exp) return Response.redirect(EXPIRED_REDIRECT_URL, 302);

  // 4️⃣ 验证签名
  const text = `${uid}:${exp}`;
  const expectedSig = await sign(text, SIGN_SECRET);
  if (expectedSig !== sig)
    return new Response("🚫 Invalid Signature", { status: 403 });

  // 5️⃣ 获取设备与应用指纹
  const ip = request.headers.get("CF-Connecting-IP") || "0.0.0.0";
  const appType = OTT_KEYWORDS.find(k => ua.includes(k)) || "Unknown";
  const deviceBase = await getDeviceFingerprint(ua, ip, uid, SIGN_SECRET); // 设备唯一指纹
  const appFingerprint = await sign(`${deviceBase}:${appType}`, SIGN_SECRET); // 设备+App 唯一标识

  // 6️⃣ 从 KV 获取绑定数据
  const key = `uid:${uid}`;
  let storedData = [];
  try {
    const json = await UID_BINDINGS.get(key);
    if (json) storedData = JSON.parse(json);
  } catch (err) {
    return new Response("⚠️ KV 读取失败，请检查配置。", { status: 500 });
  }

  // 🧠 检查是否为同一设备
  const sameDevice = storedData.some(entry => entry.device === deviceBase);

  // ✅ 如果同设备且已绑定相同 App，不阻止
  if (storedData.some(entry => entry.appFingerprint === appFingerprint)) {
    return proxyToGitHub(request, url, path, GITHUB_PAGES_URL);
  }

  // ✅ 如果是同一设备但不同 OTT App，允许最多 3 个
  if (sameDevice) {
    const appsOnDevice = storedData.filter(entry => entry.device === deviceBase);
    if (appsOnDevice.length >= MAX_APP_PER_DEVICE) {
      return Response.redirect(DEVICE_CONFLICT_URL, 302);
    }
    storedData.push({ device: deviceBase, appFingerprint, appType });
    await UID_BINDINGS.put(key, JSON.stringify(storedData));
    console.log(`✅ UID ${uid} 添加第 ${appsOnDevice.length + 1} 个 OTT 应用: ${appType}`);
    return proxyToGitHub(request, url, path, GITHUB_PAGES_URL);
  }

  // 🚫 不同设备登入：封锁
  if (storedData.length > 0 && !sameDevice) {
    return Response.redirect(DEVICE_CONFLICT_URL, 302);
  }

  // 🆕 首次登入：绑定新设备
  if (storedData.length === 0) {
    storedData.push({ device: deviceBase, appFingerprint, appType });
    await UID_BINDINGS.put(key, JSON.stringify(storedData));
    console.log(`✅ UID ${uid} 首次绑定设备与应用: ${appType}`);
    return proxyToGitHub(request, url, path, GITHUB_PAGES_URL);
  }

  // 默认转发
  return proxyToGitHub(request, url, path, GITHUB_PAGES_URL);
}

/**
 * 🌐 转发到 GitHub Pages
 */
async function proxyToGitHub(request, url, path, baseUrl) {
  const target = `${baseUrl}${path}${url.search}`;
  return fetch(target, request);
}

/**
 * 🔐 HMAC SHA256 签名
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
 * 📱 设备指纹（加入 IP + UA + UID）
 */
async function getDeviceFingerprint(ua, ip, uid, secret) {
  const cleanUA = ua.replace(/\s+/g, " ").trim().slice(0, 100);
  const base = `${uid}:${ip}:${cleanUA}`;
  return await sign(base, secret);
}
