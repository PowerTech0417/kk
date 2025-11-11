addEventListener("fetch", event => {
  event.respondWith(handleRequest(event.request));
});

async function handleRequest(request) {
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
  const isAndroid = ua.includes("Android");
  const isTV = /TV|AFT|MiBOX|SmartTV|BRAVIA|SHIELD|AndroidTV/i.test(ua);
  const appType = OTT_KEYWORDS.find(k => ua.includes(k)) || (isTV ? "OTT-TV-Unknown" : null);

  // 1️⃣ 参数验证
  if (!isAndroid || !appType) {
    console.log("🚫 非 OTT 应用访问，重定向至说明页");
    return Response.redirect(NON_OTT_REDIRECT_URL, 302);
  }

  const uid = params.get("uid");
  const exp = Number(params.get("exp"));
  const sig = params.get("sig");
  if (!uid || !exp || !sig)
    return new Response("🚫 Invalid Link: Missing parameters", { status: 403 });

  // 2️⃣ 过期时间检查（UTC+8）
  const malaysiaNow = Date.now() + 8 * 60 * 60 * 1000;
  if (malaysiaNow > exp) {
    console.log(`⏰ 链接已过期 UID=${uid}`);
    return Response.redirect(EXPIRED_REDIRECT_URL, 302);
  }

  // 3️⃣ 签名验证
  const text = `${uid}:${exp}`;
  const expectedSig = await sign(text, SIGN_SECRET);
  const sigValid = await timingSafeCompare(expectedSig, sig);
  if (!sigValid) {
    console.log(`🚫 签名验证失败 UID=${uid}`);
    return new Response("🚫 Invalid Signature", { status: 403 });
  }

  // 4️⃣ 生成设备指纹（忽略版本号）
  const appFingerprint = await getAppFingerprint(ua, uid, SIGN_SECRET, appType);

  // 5️⃣ 从 KV 读取绑定与封锁状态
  const key = `uid:${uid}`;
  const bannedKey = `banned:${uid}`;

  let stored = null;
  let bannedRecord = null;

  try {
    stored = await UID_BINDINGS.get(key, "json");
    bannedRecord = await UID_BINDINGS.get(bannedKey, "json");
  } catch (e) {
    console.error(`⚠️ KV Read/Parse Error: ${e}`);
    return new Response("Service temporarily unavailable. (K-Err)", { status: 503 });
  }

  // 6️⃣ 手动封锁逻辑：被封锁的 UID 永久禁止访问
  if (bannedRecord) {
    console.log(`🚫 UID=${uid} 被手动封锁，拒绝访问`);
    return Response.redirect(DEVICE_CONFLICT_URL, 302);
  }

  // 7️⃣ 首次绑定 / 已绑定检查（不自动封锁）
  if (!stored || !stored.fingerprint) {
    // ✅ 首次绑定
    const toStore = {
      fingerprint: appFingerprint,
      appType: appType,
      createdAt: new Date().toISOString()
    };
    await UID_BINDINGS.put(key, JSON.stringify(toStore));
    console.log(`✅ UID=${uid} 首次绑定成功 App=${appType}`);
  } else {
    const isSameAppInstance = appFingerprint === stored.fingerprint;
    if (isSameAppInstance) {
      console.log(`🟩 UID=${uid} 同设备访问 ${appType}`);
    } else {
      // ⚠️ 不自动封锁，只提示不同设备
      console.log(`⚠️ UID=${uid} 检测到不同设备/App 登录，但未封锁`);
      // 可选：是否要覆盖旧绑定
      const updated = {
        fingerprint: appFingerprint,
        appType: appType,
        updatedAt: new Date().toISOString()
      };
      await UID_BINDINGS.put(key, JSON.stringify(updated));
    }
  }

  // ✅ 通过验证 → 正常访问
  return fetch(`${GITHUB_PAGES_URL}${path}${url.search}`, request);
}

// =========================================================================
// 🔐 辅助函数
// =========================================================================

function hexToBuffer(hex) {
  if (hex.length % 2 !== 0) throw new Error("Invalid hex string length");
  const arr = new Uint8Array(hex.length / 2);
  for (let i = 0; i < hex.length; i += 2)
    arr[i / 2] = parseInt(hex.substring(i, i + 2), 16);
  return arr.buffer;
}

async function timingSafeCompare(aHex, bHex) {
  try {
    if (aHex.length !== bHex.length) return false;
    const a = hexToBuffer(aHex);
    const b = hexToBuffer(bHex);
    return await crypto.subtle.timingSafeEqual(a, b);
  } catch {
    return aHex === bHex; // fallback
  }
}

async function sign(text, secret) {
  const key = await crypto.subtle.importKey(
    "raw",
    new TextEncoder().encode(secret),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"]
  );
  const signature = await crypto.subtle.sign(
    "HMAC",
    key,
    new TextEncoder().encode(text)
  );
  return Array.from(new Uint8Array(signature))
    .map(b => b.toString(16).padStart(2, "0"))
    .join("");
}

async function getAppFingerprint(ua, uid, secret, appType) {
  const VERSION_REGEX = new RegExp(`(${appType})/[\\d\\.]+`, "gi");
  let cleanUA = ua.replace(VERSION_REGEX, `$1`);
  cleanUA = cleanUA.replace(/\s+/g, " ").trim().slice(0, 120);
  const base = `${uid}:${appType}:${cleanUA}`;
  return await sign(base, secret);
}
