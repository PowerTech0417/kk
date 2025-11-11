addEventListener("fetch", event => {
  event.respondWith(handleRequest(event.request));
});

const ADMIN_SECRET = "change_this_to_a_strong_admin_secret"; // 部署时请改为强密钥

async function handleRequest(request) {
  const url = new URL(request.url);
  const path = url.pathname;
  const params = url.searchParams;

  // === 管理员 API（可选）：解除封锁，需 POST 并带 x-admin-key 头 ===
  if (path === "/admin/unban" && request.method === "POST") {
    const adminKey = request.headers.get("x-admin-key");
    if (!adminKey || adminKey !== ADMIN_SECRET) {
      return new Response("Unauthorized", { status: 403 });
    }
    // 允许通过 body 指定 uid 或批量
    let body = {};
    try {
      body = await request.json().catch(() => ({}));
    } catch {}
    const uid = body.uid;
    if (!uid) return new Response("Missing uid", { status: 400 });
    const bannedKey = `banned:${uid}`;
    try {
      await UID_BINDINGS.delete(bannedKey);
      return new Response(JSON.stringify({ ok: true, uid }), {
        headers: { "Content-Type": "application/json;charset=utf-8" },
      });
    } catch (e) {
      return new Response("KV error", { status: 500 });
    }
  }

  // === ⚙️ 配置区 ===
  const GITHUB_PAGES_URL = "https://modskyshop168-sudo.github.io/cc/";
  const EXPIRED_REDIRECT_URL = "https://life4u22.blogspot.com/p/powertech.html";
  const DEVICE_CONFLICT_URL = "https://life4u22.blogspot.com/p/id-ban.html";
  const NON_OTT_REDIRECT_URL = "https://life4u22.blogspot.com/p/ott-channel-review.html";
  const SIGN_SECRET = "mySuperSecretKey"; // 请部署时替换为真实签名密钥
  const OTT_KEYWORDS = ["OTT Player", "OTT TV", "OTT Navigator"];
  // =================

  const ua = request.headers.get("User-Agent") || "";
  const isAndroid = ua.includes("Android");
  const isTV = /TV|AFT|MiBOX|SmartTV|BRAVIA|SHIELD|AndroidTV/i.test(ua);
  const appType = OTT_KEYWORDS.find(k => ua.includes(k)) || (isTV ? "OTT-TV-Unknown" : null);

  // 1️⃣ 非 OTT 请求重定向到说明页
  if (!isAndroid || !appType) {
    return Response.redirect(NON_OTT_REDIRECT_URL, 302);
  }

  // 读取并验证参数
  const uid = params.get("uid");
  const exp = Number(params.get("exp"));
  const sig = params.get("sig");
  if (!uid || !exp || !sig) {
    return new Response("🚫 Invalid Link: Missing parameters", { status: 403 });
  }

  // 2️⃣ 过期检查 (UTC+8)
  const malaysiaNow = Date.now() + 8 * 60 * 60 * 1000;
  if (malaysiaNow > exp) {
    return Response.redirect(EXPIRED_REDIRECT_URL, 302);
  }

  // 3️⃣ 签名验证 (确保请求由你生成)
  const text = `${uid}:${exp}`;
  const expectedSig = await sign(text, SIGN_SECRET);
  const sigValid = await timingSafeCompare(expectedSig, sig);
  if (!sigValid) {
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
    return new Response("Service temporarily unavailable. (K-Err)", { status: 503 });
  }

  // 6️⃣ 永久封锁：一旦存在 bannedRecord，直接拒绝访问（Worker 不会自动解封）
  if (bannedRecord) {
    return Response.redirect(DEVICE_CONFLICT_URL, 302);
  }

  // 7️⃣ 首次绑定或校验已绑定指纹
  if (!stored || !stored.fingerprint) {
    // 首次绑定：写入绑定信息
    const toStore = {
      fingerprint: appFingerprint,
      appType: appType,
      createdAt: new Date().toISOString()
    };
    try {
      await UID_BINDINGS.put(key, JSON.stringify(toStore));
    } catch (e) {
      return new Response("KV write error", { status: 500 });
    }
  } else {
    // 已有绑定：检查是否为同一应用实例（指纹）
    const isSameAppInstance = appFingerprint === stored.fingerprint;
    if (!isSameAppInstance) {
      // 不同设备 -> 永久封锁账户并删除绑定
      const bannedInfo = {
        reason: "device_conflict",
        sig,
        appType,
        bannedAt: new Date().toISOString()
      };
      try {
        await UID_BINDINGS.put(bannedKey, JSON.stringify(bannedInfo)); // 永久封锁（无TTL）
        await UID_BINDINGS.delete(key);
      } catch (e) {
        // 如果 KV 操作失败，仍要返回封锁页（保守策略）
      }
      return Response.redirect(DEVICE_CONFLICT_URL, 302);
    }
    // 同设备：继续访问
  }

  // 8️⃣ 放行请求到 GitHub Pages
  return fetch(`${GITHUB_PAGES_URL}${path}${url.search}`, request);
}

// =========================================================================
// 🔐 辅助函数
// =========================================================================

function hexToBuffer(hex) {
  if (hex.length % 2 !== 0) throw new Error("Invalid hex string length");
  const arr = new Uint8Array(hex.length / 2);
  for (let i = 0; i < hex.length; i += 2) arr[i / 2] = parseInt(hex.substring(i, i + 2), 16);
  return arr.buffer;
}

async function timingSafeCompare(aHex, bHex) {
  try {
    if (!aHex || !bHex || aHex.length !== bHex.length) return false;
    const a = hexToBuffer(aHex);
    const b = hexToBuffer(bHex);
    // 某些环境可能没有 timingSafeEqual；若没有则 fallback
    if (crypto.subtle && typeof crypto.subtle.timingSafeEqual === "function") {
      return await crypto.subtle.timingSafeEqual(a, b);
    } else {
      // 常规字节比较（短时间内执行）
      let res = 0;
      const va = new Uint8Array(a);
      const vb = new Uint8Array(b);
      for (let i = 0; i < va.length; i++) res |= va[i] ^ vb[i];
      return res === 0;
    }
  } catch {
    return aHex === bHex;
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
  const signature = await crypto.subtle.sign("HMAC", key, new TextEncoder().encode(text));
  return Array.from(new Uint8Array(signature)).map(b => b.toString(16).padStart(2, "0")).join("");
}

async function getAppFingerprint(ua, uid, secret, appType) {
  const VERSION_REGEX = new RegExp(`(${appType})/[\\d\\.]+`, "gi");
  let cleanUA = ua.replace(VERSION_REGEX, `$1`);
  cleanUA = cleanUA.replace(/\s+/g, " ").trim().slice(0, 120);
  const base = `${uid}:${appType}:${cleanUA}`;
  return await sign(base, secret);
}
