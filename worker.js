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
  const isAndroid = /Android/i.test(ua);
  const isTV = /TV|AFT|MiBOX|SmartTV|BRAVIA|SHIELD|AndroidTV/i.test(ua);

  // 更宽松、不区分大小写的 appType 检测
  const loweredUA = ua.toLowerCase();
  const appType = OTT_KEYWORDS.find(k => loweredUA.includes(k.toLowerCase())) || (isTV ? "OTT-TV-Unknown" : null);

  // 非 Android 或 非 OTT 应用/设备 -> 重定向到非 OTT 页面
  if (!isAndroid || !appType) {
    return Response.redirect(NON_OTT_REDIRECT_URL, 302);
  }

  // 参数验证
  const uid = params.get("uid");
  const expRaw = params.get("exp");
  const sig = params.get("sig");
  if (!uid || !expRaw || !sig) {
    return new Response("🚫 Invalid Link: Missing parameters (uid/exp/sig).", { status: 403 });
  }

  // 处理 exp：接受秒或毫秒，统一转成毫秒整数
  let exp = Number(expRaw);
  if (!Number.isFinite(exp) || exp <= 0) {
    return new Response("🚫 Invalid Link: bad exp value.", { status: 403 });
  }
  if (exp < 1e12) { // 看起来像秒 -> 转成毫秒
    exp = exp * 1000;
  }

  const now = Date.now(); // UTC ms
  if (now > exp) {
    return Response.redirect(EXPIRED_REDIRECT_URL, 302);
  }

  // 签名验证
  const text = `${uid}:${Math.floor(exp / 1000)}`; // 推荐签名使用秒级时间戳
  const expectedSig = await sign(text, SIGN_SECRET);
  const sigValid = timingSafeCompareHex(expectedSig, sig);

  if (!sigValid) {
    console.warn(`Signature mismatch for uid=${uid}. expected=${expectedSig} provided=${sig}`);
    return new Response("🚫 Invalid Signature", { status: 403 });
  }

  // 设备指纹（仅基于 UA 与 uid）
  let deviceFingerprint;
  try {
    deviceFingerprint = await getDeviceFingerprint(ua, uid, SIGN_SECRET);
  } catch (e) {
    console.error("Device fingerprint generation failed:", e);
    return new Response("Service temporarily unavailable. (Fingerprint Err)", { status: 503 });
  }

  // KV 操作
  const key = `uid:${uid}`;
  let stored = null;
  try {
    stored = await UID_BINDINGS.get(key, "json");
  } catch (e) {
    console.error(`KV Read Error for ${key}:`, e);
    return new Response("Service temporarily unavailable. (K-Read Err)", { status: 503 });
  }

  // 首次绑定
  if (!stored) {
    const toStore = {
      device: deviceFingerprint,
      apps: [appType],
      createdAt: new Date().toISOString()
    };
    try {
      await UID_BINDINGS.put(key, JSON.stringify(toStore), { expirationTtl: 0 }); // ✅ 永不过期
      console.log(`✅ UID ${uid} 首次绑定 device=${deviceFingerprint}, app=${appType}`);
    } catch (e) {
      console.error(`KV Put Error (initial) for ${key}:`, e);
      return new Response("Service temporarily unavailable. (K-Put Err)", { status: 503 });
    }
  }
  // 同设备访问
  else if (stored.device === deviceFingerprint) {
    if (!Array.isArray(stored.apps)) stored.apps = [];

    if (!stored.apps.includes(appType)) {
      stored.apps.push(appType);
      try {
        await UID_BINDINGS.put(key, JSON.stringify(stored), { expirationTtl: 0 }); // ✅ 永不过期
        console.log(`🟡 UID ${uid} 同设备使用新应用，新增 ${appType}`);
      } catch (e) {
        console.error(`KV Put Error (update apps) for ${key}:`, e);
      }
    } else {
      console.log(`🟩 UID ${uid} 同设备访问 ${appType}`);
    }
  }
  // 不同设备 -> 冲突
  else {
    console.warn(`🚫 UID ${uid} 不同设备登入。stored.device=${stored.device} current=${deviceFingerprint}`);
    return Response.redirect(DEVICE_CONFLICT_URL, 302);
  }

  // 转发到 GitHub Pages
  try {
    const dest = new URL(path + url.search, GITHUB_PAGES_URL).toString();
    return fetch(dest, request);
  } catch (e) {
    console.error("Fetch proxy failed:", e);
    return new Response("Service temporarily unavailable. (Proxy Err)", { status: 503 });
  }
}

/* ---------- 辅助函数 ---------- */

/** 将十六进制字符串转换为 Uint8Array */
function hexToUint8Array(hex) {
  if (typeof hex !== "string") throw new Error("hex must be string");
  const s = hex.trim();
  if (s.length % 2 !== 0) throw new Error("Invalid hex string length");
  const out = new Uint8Array(s.length / 2);
  for (let i = 0; i < s.length; i += 2) {
    const byte = Number.parseInt(s.substring(i, i + 2), 16);
    if (Number.isNaN(byte)) throw new Error("Invalid hex string");
    out[i / 2] = byte;
  }
  return out;
}

/** 常量时间比较两个 hex 字符串（防止时序攻击） */
function timingSafeCompareHex(aHex, bHex) {
  try {
    if (!aHex || !bHex) return false;
    if (aHex.length !== bHex.length) return false;
    const a = hexToUint8Array(aHex);
    const b = hexToUint8Array(bHex);
    let diff = 0;
    for (let i = 0; i < a.length; i++) {
      diff |= a[i] ^ b[i];
    }
    return diff === 0;
  } catch (e) {
    console.error("timingSafeCompareHex error:", e);
    return false;
  }
}

/** 生成 HMAC-SHA256 签名，并以 hex 返回 */
async function sign(text, secret) {
  const enc = new TextEncoder();
  const keyData = enc.encode(secret);
  const algo = { name: "HMAC", hash: { name: "SHA-256" } };
  const key = await crypto.subtle.importKey("raw", keyData, algo, false, ["sign"]);
  const sigBuffer = await crypto.subtle.sign("HMAC", key, enc.encode(text));
  const sigArray = Array.from(new Uint8Array(sigBuffer));
  return sigArray.map(b => b.toString(16).padStart(2, "0")).join("");
}

/** 基于 uid + 清理后的 UA 生成设备指纹（返回 hex） */
async function getDeviceFingerprint(ua, uid, secret) {
  const cleanUA = (ua || "").replace(/\s+/g, " ").trim().slice(0, 120);
  const base = `${uid}:${cleanUA}`;
  return await sign(base, secret);
}
