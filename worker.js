addEventListener("fetch", event => {
  event.respondWith(handleRequest(event.request));
});

// 引入常量
const OTT_KEYWORDS = ["OTT Player", "OTT TV", "OTT Navigator"];
const UA_PREFIX_LENGTH = 50; // 用来识别设备的前缀长度

async function handleRequest(request) {
  const url = new URL(request.url);
  const path = url.pathname;
  const params = url.searchParams;

  // === ⚙️ 配置区 (保持不变) ===
  const GITHUB_PAGES_URL = "https://modskyshop168-sudo.github.io/cc/";
  const EXPIRED_REDIRECT_URL = "https://life4u22.blogspot.com/p/powertech.html";
  const DEVICE_CONFLICT_URL = "https://life4u22.blogspot.com/p/id-ban.html";
  const NON_OTT_REDIRECT_URL = "https://life4u22.blogspot.com/p/ott-channel-review.html";
  const SIGN_SECRET = "mySuperSecretKey"; 
  // =================

  const ua = request.headers.get("User-Agent") || "";
  const isAndroid = ua.includes("Android");
  const isTV = /TV|AFT|MiBOX|SmartTV|BRAVIA|SHIELD|AndroidTV/i.test(ua);
  const appType = OTT_KEYWORDS.find(k => ua.includes(k)) || (isTV ? "OTT-TV-Unknown" : null);

  // 1. 预检查和参数验证 (保持不变)
  if (!isAndroid || !appType) return Response.redirect(NON_OTT_REDIRECT_URL, 302);
  const uid = params.get("uid");
  const exp = Number(params.get("exp"));
  const sig = params.get("sig");
  if (!uid || !exp || !sig) return new Response("🚫 Invalid Link: Missing parameters", { status: 403 });

  // 2. 过期时间检查 (保持不变)
  const malaysiaNow = Date.now() + 8 * 60 * 60 * 1000;
  if (malaysiaNow > exp) return Response.redirect(EXPIRED_REDIRECT_URL, 302);

  // 3. 签名验证 (保持不变)
  const text = `${uid}:${exp}`;
  const expectedSig = await sign(text, SIGN_SECRET);
  const sigValid = await timingSafeCompare(expectedSig, sig);
  if (!sigValid) return new Response("🚫 Invalid Signature", { status: 403 });

  // 4. KV 读取 (保持不变)
  const key = `uid:${uid}`;
  let stored = null;
  try {
    stored = await UID_BINDINGS.get(key, "json");
  } catch (e) {
    console.error(`KV Read/Parse Error for ${key}:`, e);
    return new Response("Service temporarily unavailable. (K-Err)", { status: 503 });
  }

  // 5. 新设备指纹 (UA 前缀，用于匹配)
  // 核心逻辑改变：我们使用一个简单的 UA 前缀作为设备的标识
  const cleanUA = ua.replace(/\s+/g, " ").trim();
  const currentUAPrefix = cleanUA.slice(0, UA_PREFIX_LENGTH);

  // 6. 核心设备绑定与验证逻辑
  
  // 首次登入 (或 KV 被清除后)
  if (!stored || !stored.device_ua_prefix) {
    const toStore = { 
      device_ua_prefix: currentUAPrefix, // 存储第一个应用的 UA 前缀作为基准
      apps: [appType], 
      createdAt: new Date().toISOString() 
    };
    await UID_BINDINGS.put(key, JSON.stringify(toStore));
    console.log(`✅ UID ${uid} 首次绑定设备，基准前缀: ${currentUAPrefix}`);
  } 
  // 已有绑定记录
  else {
    const storedUAPrefix = stored.device_ua_prefix;
    
    // 验证：检查当前 UA 前缀是否与存储的基准前缀高度相似 (即，是否相等)
    // ⚠️ 注意: 这里我们仍然使用简单的字符串相等，如果不同 App 的 UA 前缀略有不同，需要根据实际情况调整为模糊匹配 (例如，使用 .includes())
    const isSameDevice = currentUAPrefix === storedUAPrefix;

    if (isSameDevice) {
        // 同一设备，允许登入
        if (!stored.apps.includes(appType)) {
            // 新的应用，添加到 apps 列表
            stored.apps.push(appType);
            await UID_BINDINGS.put(key, JSON.stringify(stored));
            console.log(`🟡 UID ${uid} 同设备使用新应用，新增 ${appType}`);
        } else {
            console.log(`🟩 UID ${uid} 同设备访问 ${appType}`);
        }
    } else {
        // 不同设备 (UA 前缀不匹配) → 封锁
        console.log(`🚫 UID ${uid} 不同设备登入。Stored: "${storedUAPrefix}", Current: "${currentUAPrefix}"`);
        return Response.redirect(DEVICE_CONFLICT_URL, 302);
    }
  }

  // ✅ 正常访问
  return fetch(`${GITHUB_PAGES_URL}${path}${url.search}`, request);
}

// =========================================================================
// 签名辅助函数 (保持不变，因为它们用于签名验证，不受设备绑定逻辑影响)
// =========================================================================

// 辅助函数：将十六进制字符串转换为 ArrayBuffer
function hexToBuffer(hex) {
    if (hex.length % 2 !== 0) {
        throw new Error("Invalid hex string length");
    }
    const arr = new Uint8Array(hex.length / 2);
    for (let i = 0; i < hex.length; i += 2) {
        arr[i / 2] = parseInt(hex.substring(i, i + 2), 16);
    }
    return arr.buffer;
}

/** 🔑 使用 timingSafeEqual 进行时间安全比较 */
async function timingSafeCompare(aHex, bHex) {
    try {
        if (aHex.length !== bHex.length) {
            return false;
        }
        const a = hexToBuffer(aHex);
        const b = hexToBuffer(bHex);
        
        return await crypto.subtle.timingSafeEqual(a, b);
    } catch (e) {
        console.error("Timing safe comparison failed, falling back:", e);
        return aHex === bHex;
    }
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
  
  // 返回十六进制字符串
  return Array.from(new Uint8Array(signature))
    .map(b => b.toString(16).padStart(2, "0"))
    .join("");
}

