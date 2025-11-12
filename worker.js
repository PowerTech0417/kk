addEventListener("fetch", event => {
  event.respondWith(handleRequest(event.request, event));
});

async function handleRequest(request, event) {
  const url = new URL(request.url);
  const path = url.pathname;
  const params = url.searchParams;

  // === ⚙️ 配置区 ===
  const GITHUB_PAGES_URL = "https://modskyshop168-sudo.github.io/cc/";
  const EXPIRED_REDIRECT_URL = "https://life4u22.blogspot.com/p/powertech.html";
  const DEVICE_CONFLICT_URL = "https://life4u22.blogspot.com/p/id-ban.html";
  const NON_OTT_REDIRECT_URL = "https://life4u22.blogspot.com/p/ott-channel-review.html";
  const SIGN_SECRET = "mySuperSecretKey"; 
  const OTT_KEYWORDS = ["OTT Player", "OTT TV", "OTT Navigator"];
  // =================

  const ua = request.headers.get("User-Agent") || "";

  // === ✅ Android 全设备识别 ===
  const isAndroid = /Android/i.test(ua);
  const isTV = /TV|AFT|MiBOX|SmartTV|BRAVIA|SHIELD|AndroidTV|Chromecast|FireTV/i.test(ua);
  const isProjector = /Projector|XGIMI|Dangbei|JMGO/i.test(ua);
  const isCar = /Car|HeadUnit|Teyes|Joying|Dasaita|AndroidAuto/i.test(ua);
  const isHandheld = /Odin|GPD|Anbernic|Retroid|G Cloud/i.test(ua);
  const isBox = /Mecool|Ugoos|Tanix|Minix/i.test(ua);

  const appType = OTT_KEYWORDS.find(k => ua.includes(k)) || (isTV ? "OTT-TV-Unknown" : null);

  // ❌ 非 OTT 设备/非 Android 
  if (!isAndroid || !appType) {
    return Response.redirect(NON_OTT_REDIRECT_URL, 302);
  }

  // 参数验证
  const uid = params.get("uid");
  const exp = Number(params.get("exp"));
  const sig = params.get("sig");
  if (!uid || !exp || !sig) {
    return new Response("🚫 Invalid Link: Missing parameters", { status: 403 });
  }

  // 检查过期时间（马来西亚时区：UTC+8）
  const malaysiaNow = Date.now() + 8 * 60 * 60 * 1000;
  if (malaysiaNow > exp) {
    return Response.redirect(EXPIRED_REDIRECT_URL, 302);
  }

  // 签名验证
  const text = `${uid}:${exp}`;
  const expectedSig = await sign(text, SIGN_SECRET);
  const sigValid = timingSafeCompare(expectedSig, sig);
  if (!sigValid) {
    return new Response("🚫 Invalid Signature", { status: 403 });
  }

  // 📱 设备指纹（不含 IP 和 appType，代表物理设备）
  const deviceFingerprint = await getDeviceFingerprint(ua, uid, SIGN_SECRET);

  // 确保 KV 可用
  if (typeof UID_BINDINGS === "undefined") {
    return new Response("Service unavailable. (KV missing)", { status: 503 });
  }

  const key = `uid:${uid}`;
  let stored = null;

  try {
    stored = await UID_BINDINGS.get(key, "json");
  } catch (e) {
    return new Response("Service temporarily unavailable. (KV read error)", { status: 503 });
  }

  // 首次登入
  if (!stored) {
    const toStore = { device: deviceFingerprint, apps: [appType], createdAt: new Date().toISOString() };
    await UID_BINDINGS.put(key, JSON.stringify(toStore));
  } 
  // 同物理设备
  else if (stored.device === deviceFingerprint) {
    if (!stored.apps.includes(appType)) {
      stored.apps.push(appType);
      await UID_BINDINGS.put(key, JSON.stringify(stored));
    }
  } 
  // 不同设备 → 封锁
  else {
    return Response.redirect(DEVICE_CONFLICT_URL, 302);
  }

  // ✅ 正常访问 (修正 fetch 参数)
  return fetch(`${GITHUB_PAGES_URL}${path}${url.search}`, {
    method: request.method,
    headers: request.headers,
    body: request.body,
    redirect: "follow"
  });
}

/** 🔑 HMAC 签名生成 (SHA-256) */
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

/** ⏱ 时间安全比较（兼容 Cloudflare Worker） */
function timingSafeCompare(aHex, bHex) {
  if (aHex.length !== bHex.length) return false;
  let diff = 0;
  for (let i = 0; i < aHex.length; i++) {
    diff |= aHex.charCodeAt(i) ^ bHex.charCodeAt(i);
  }
  return diff === 0;
}

/** 📱 设备指纹（不含 IP 和 appType，代表物理设备）*/
async function getDeviceFingerprint(ua, uid, secret) {
  const cleanUA = ua.toLowerCase().replace(/\s+/g, " ").trim().slice(0, 120);
  const base = `${uid}:${cleanUA}`;
  return await sign(base, secret);
}
