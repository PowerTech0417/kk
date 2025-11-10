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
  const SIGN_SECRET = "mySuperSecretKey";
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

  // 1️⃣ 解析签名参数
  const uid = params.get("uid");
  const exp = Number(params.get("exp"));
  const sig = params.get("sig");
  if (!uid || !exp || !sig)
    return new Response("🚫 Invalid Link", { status: 403 });

  // 🇲🇾 当前马来西亚时间（UTC+8）
  const malaysiaNow = new Date(Date.now() + 8 * 60 * 60 * 1000);
  const nowMillis = malaysiaNow.getTime();
  const formattedMY = malaysiaNow.toISOString().replace("T", " ").slice(0, 19);

  // 2️⃣ 过期检查
  if (nowMillis > exp) return Response.redirect(EXPIRED_REDIRECT_URL, 302);

  // 3️⃣ 验证签名
  const text = `${uid}:${exp}`;
  const expectedSig = await sign(text, SIGN_SECRET);
  if (expectedSig !== sig)
    return new Response("🚫 Invalid Signature", { status: 403 });

  // 4️⃣ 生成设备指纹（IP + UA + UID）
  const ua = request.headers.get("User-Agent") || "";
  const ip = request.headers.get("CF-Connecting-IP") || "0.0.0.0";
  const deviceFingerprint = await getDeviceFingerprint(ua, ip, uid, SIGN_SECRET);

  // 5️⃣ 检查 KV 是否已绑定
  const key = `uid:${uid}`;
  let storedFingerprint = null;
  try {
    storedFingerprint = await UID_BINDINGS.get(key);
  } catch (err) {
    return new Response("⚠️ KV 读取失败，请检查配置。", { status: 500 });
  }

  // 🚫 不同设备登入
  if (storedFingerprint && storedFingerprint !== deviceFingerprint) {
    return Response.redirect(DEVICE_CONFLICT_URL, 302);
  }

  // ✅ 首次登入 → 绑定并显示提示页（自动跳转 5 秒）
  if (!storedFingerprint) {
    await UID_BINDINGS.put(key, deviceFingerprint);
    const target = `${GITHUB_PAGES_URL}${path}${url.search}`;
    return new Response(
      `
      <html lang="zh">
        <head>
          <meta charset="UTF-8" />
          <meta name="viewport" content="width=device-width, initial-scale=1.0" />
          <title>设备已绑定成功</title>
          <meta http-equiv="refresh" content="5; url=${target}" />
          <style>
            body {
              background:#0a1a3a;
              color:white;
              font-family:Arial, sans-serif;
              text-align:center;
              padding-top:15%;
            }
            h1 {
              font-size:2.2em;
              color:#00ff88;
            }
            p {
              font-size:1.1em;
              opacity:0.9;
            }
            a {
              color:#00c3ff;
              text-decoration:none;
              font-weight:bold;
            }
            .countdown {
              margin-top:20px;
              font-size:1.2em;
              color:#ffcc00;
            }
            .time {
              margin-top:15px;
              color:#aaa;
              font-size:1em;
            }
          </style>
        </head>
        <body>
          <h1>✅ 设备已成功绑定</h1>
          <p>UID：<b>${uid}</b></p>
          <p>绑定时间（马来西亚）：<br><b>${formattedMY}</b></p>
          <p>系统将在 <span id="seconds">5</span> 秒后自动进入内容。</p>
          <div class="countdown">若未跳转，请 <a href="${target}">点此进入</a></div>

          <script>
            let s = 5;
            const el = document.getElementById("seconds");
            const timer = setInterval(()=>{
              s--;
              if(s <= 0) clearInterval(timer);
              el.textContent = s;
            },1000);
          </script>
        </body>
      </html>
      `,
      { status: 200, headers: { "content-type": "text/html; charset=utf-8" } }
    );
  }

  // 6️⃣ 已绑定设备 → 直接访问内容
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
 * 📱 设备指纹（UID + IP + UA）
 */
async function getDeviceFingerprint(ua, ip, uid, secret) {
  const cleanUA = ua.replace(/\s+/g, " ").trim().slice(0, 100);
  const base = `${uid}:${ip}:${cleanUA}`;
  return await sign(base, secret);
}
