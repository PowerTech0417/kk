addEventListener("fetch", event => {
  event.respondWith(handleRequest(event.request));
});

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
  const OTT_KEYWORDS = ["OTT Player", "OTT TV", "OTT Navigator"];
  // =================

  const ua = request.headers.get("User-Agent") || "";
  const isAndroid = ua.includes("Android");
  const isTV = /TV|AFT|MiBOX|SmartTV|BRAVIA|SHIELD|AndroidTV/i.test(ua);
  const appType = OTT_KEYWORDS.find(k => ua.includes(k)) || (isTV ? "OTT-TV-Unknown" : null);

  // 1. 预检查和参数验证
  if (!isAndroid || !appType) return Response.redirect(NON_OTT_REDIRECT_URL, 302);
  const uid = params.get("uid");
  const exp = Number(params.get("exp"));
  const sig = params.get("sig");
  if (!uid || !exp || !sig) return new Response("🚫 Invalid Link: Missing parameters", { status: 403 });

  // 2. 过期时间检查（UTC+8）
  const malaysiaNow = Date.now() + 8 * 60 * 60 * 1000;
  if (malaysiaNow > exp) return Response.redirect(EXPIRED_REDIRECT_URL, 302);

  // 3. 签名验证 (防篡改)
  const text = `${uid}:${exp}`;
  const expectedSig = await sign(text, SIGN_SECRET);
  const sigValid = await timingSafeCompare(expectedSig, sig); // 使用时间安全比较
  if (!sigValid) return new Response("🚫 Invalid Signature", { status: 403 });

  // 4. 关键：生成应用实例指纹 (已修复：移除版本号)
  const appFingerprint = await getAppFingerprint(ua, uid, SIGN_SECRET, appType);

  // 5. KV 读取
  const key = `uid:${uid}`;
  let stored = null;
  try {
    stored = await UID_BINDINGS.get(key, "json");
  } catch (e) {
    console.error(`KV Read/Parse Error for ${key}:`, e);
    return new Response("Service temporarily unavailable. (K-Err)", { status: 503 });
  }

  // 6. 核心设备绑定与验证逻辑
  
  // 首次登入 (或 KV 被清除后)
  if (!stored || !stored.fingerprint) {
    const toStore = { 
      fingerprint: appFingerprint, // 存储唯一的指纹
      appType: appType,
      createdAt: new Date().toISOString() 
    };
    await UID_BINDINGS.put(key, JSON.stringify(toStore));
    console.log(`✅ UID ${uid} 首次绑定 App 实例指纹 (已忽略版本号): ${appFingerprint}`);
  } 
  // 已有绑定记录
  else {
    // 检查：当前指纹是否与存储的指纹一致
    const isSameAppInstance = appFingerprint === stored.fingerprint;

    if (isSameAppInstance) {
        // 同一应用实例登入 (版本已忽略，故可升级)
        console.log(`🟩 UID ${uid} 同应用实例访问 ${appType}`);
    } else {
        // 不同应用实例登入 → 封锁
        console.log(`🚫 UID ${uid} 不同 App/设备登入。Stored App: ${stored.appType}`);
        return Response.redirect(DEVICE_CONFLICT_URL, 302);
    }
  }

  // ✅ 正常访问
  return fetch(`${GITHUB_PAGES_URL}${path}${url.search}`, request);
}

// =========================================================================
// 辅助函数 (已更新 getAppFingerprint)
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

/** 📱 应用实例指纹（已修复：在计算指纹前移除版本号）*/
async function getAppFingerprint(ua, uid, secret, appType) {
  // 核心修复：移除当前 AppType 的版本号部分。
  // 例如，如果 appType 是 "OTT TV"，则匹配 "OTT TV/1.7.2.2" 并将其移除或替换为 "OTT TV/"
  
  // 1. 尝试匹配并移除版本号 (e.g., "OTT TV/1.7.2.2" -> "OTT TV/")
  // 此正则寻找 AppType 后跟斜杠和数字版本号的部分
  const VERSION_REGEX = new RegExp(`(${appType})/[\\d\\.]+`, "gi");
  // 替换为 AppType 本身，确保指纹只包含 App 名称，不包含版本。
  let cleanUA = ua.replace(VERSION_REGEX, `$1`); 

  // 2. 规范化：移除多余空格并截断
  cleanUA = cleanUA.replace(/\s+/g, " ").trim().slice(0, 120);
  
  // 指纹基于 UID、APP 类型和清理后的 UA (不含版本号)
  const base = `${uid}:${appType}:${cleanUA}`;
  return await sign(base, secret);
}
