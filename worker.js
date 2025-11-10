  addEventListener("fetch", event => {
  event.respondWith(handleRequest(event.request));
});

async function handleRequest(request) {
  const url = new URL(request.url);
  const path = url.pathname;
  const params = url.searchParams;

  // === ⚙️ 配置区 ===
  const GITHUB_PAGES_URL = "https://skyline5108.github.io/playlist";
  const EXPIRED_REDIRECT_URL = "https://life4u22.blogspot.com/p/powertech.html";
  const DEVICE_CONFLICT_URL = "https://life4u22.blogspot.com/p/id-ban.html";
  const NON_OTT_REDIRECT_URL = "https://life4u22.blogspot.com/p/ott-channel-review.html";
  const SIGN_SECRET = "mySuperSecretKey"; // 改成你自己的签名密钥
  const OTT_KEYWORDS = ["OTT Player", "OTT TV", "OTT Navigator"]; // 支持的 OTT APP
  const MAX_APPS_PER_DEVICE = 3; // 同一设备最多允许绑定几个 APP
  // =================

  const ua = request.headers.get("User-Agent") || "";
  const isAndroid = ua.includes("Android");
  const appType = OTT_KEYWORDS.find(k => ua.includes(k)) || null;

  if (!isAndroid || !appType) {
    return Response.redirect(NON_OTT_REDIRECT_URL, 302);
  }

  const uid = params.get("uid");
  const exp = Number(params.get("exp"));
  const sig = params.get("sig");
  if (!uid || !exp || !sig) return new Response("🚫 Invalid Link", { status: 403 });

  const malaysiaNow = new Date(Date.now() + 8 * 60 * 60 * 1000);
  const nowMillis = malaysiaNow.getTime();

  if (nowMillis > exp) return Response.redirect(EXPIRED_REDIRECT_URL, 302);

  const text = `${uid}:${exp}`;
  const expectedSig = await sign(text, SIGN_SECRET);
  if (expectedSig !== sig) return new Response("🚫 Invalid Signature", { status: 403 });

  const ip = request.headers.get("CF-Connecting-IP") || "0.0.0.0";
  const deviceFingerprint = await getDeviceFingerprint(ua, ip, uid, SIGN_SECRET);

  const key = `uid:${uid}`;
  let stored = null;
  try {
    const raw = await UID_BINDINGS.get(key);
    if (raw) stored = JSON.parse(raw);
  } catch (e) {
    return new Response("⚠️ KV 读取失败，请检查配置。", { status: 500 });
  }

  // 🟩 情况 1：首次登入
  if (!stored) {
    const toStore = { device: deviceFingerprint, apps: [appType] };
    await UID_BINDINGS.put(key, JSON.stringify(toStore));
    console.log(`✅ UID ${uid} 首次绑定设备 ${deviceFingerprint}, app=${appType}`);
    const target = `${GITHUB_PAGES_URL}${path}${url.search}`;
    return fetch(target, request);
  }

  // 🟨 情况 2：同设备
  if (stored.device === deviceFingerprint) {
    const apps = Array.isArray(stored.apps) ? stored.apps : [];
    // 如果当前 app 已绑定，直接通过
    if (apps.includes(appType)) {
      const target = `${GITHUB_PAGES_URL}${path}${url.search}`;
      return fetch(target, request);
    }

    // 如果还没绑定该 app，检查配额
    if (apps.length < MAX_APPS_PER_DEVICE) {
      apps.push(appType);
      stored.apps = [...new Set(apps)]; // 去重
      await UID_BINDINGS.put(key, JSON.stringify(stored));
      console.log(`🟩 UID ${uid} 同设备新增绑定 app=${appType}`);
      const target = `${GITHUB_PAGES_URL}${path}${url.search}`;
      return fetch(target, request);
    } else {
      return new Response("⚠️ 已达到同设备可登入的最大 APP 数量。", { status: 403 });
    }
  }

  // 🟥 情况 3：不同设备尝试登入 -> 拒绝
  console.log(`🚫 UID ${uid} 试图从不同设备登入`);
  return Response.redirect(DEVICE_CONFLICT_URL, 302);
}

/** 🔐 生成签名 */
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

/** 📱 设备指纹（根据 UID + IP + 简化 UA） */
async function getDeviceFingerprint(ua, ip, uid, secret) {
  const cleanUA = ua.replace(/\s+/g, " ").trim().slice(0, 120);
  const base = `${uid}:${ip}:${cleanUA}`;
  return await sign(base, secret);
}
