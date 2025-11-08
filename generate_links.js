import crypto from "crypto";
import fs from "fs";

const SIGN_SECRET = "MySuperSecretKey123"; // 与 Worker 保持一致
const BASE_URL = "https://ott-worker.youraccount.workers.dev"; // 部署后替换
const USERS = ["user001", "user002", "user003"];

function sign(text) {
  return crypto.createHmac("sha256", SIGN_SECRET).update(text).digest("hex");
}

const links = [];
for (const uid of USERS) {
  const exp = Date.now() + Math.floor(Math.random() * 6 + 1) * 60 * 60 * 1000; // 每个用户不同过期时间（1~6小时）
  const sig = sign(`${uid}:${exp}`);
  links.push({
    uid,
    exp,
    link: `${BASE_URL}/dist/index.html?uid=${uid}&exp=${exp}&sig=${sig}`
  });
}

fs.writeFileSync("signed_links.json", JSON.stringify(links, null, 2));
console.log("✅ 链接已生成：signed_links.json");
