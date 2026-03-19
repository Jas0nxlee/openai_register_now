/**
 * Cloudflare Email Worker — OpenAI 注册 OTP 接收器
 *
 * 功能：
 *   1. email 事件：收到邮件后解析 6 位验证码，存入 KV（TTL 600s）
 *   2. fetch 事件：提供 GET /code?email=xxx HTTP 接口，鉴权后返回验证码
 *
 * 所需 KV Namespace 绑定（名称：OTP_STORE）以及 Secret：WORKER_API_KEY
 */

// ========== 邮件文本提取 ==========

/**
 * 从 ReadableStream 读取所有字节并转为字符串
 * @param {ReadableStream} stream
 * @returns {Promise<string>}
 */
async function streamToText(stream) {
  const reader = stream.getReader();
  const chunks = [];
  while (true) {
    const { done, value } = await reader.read();
    if (done) break;
    chunks.push(value);
  }
  const total = chunks.reduce((acc, c) => acc + c.length, 0);
  const buf = new Uint8Array(total);
  let off = 0;
  for (const c of chunks) {
    buf.set(c, off);
    off += c.length;
  }
  return new TextDecoder("utf-8", { fatal: false }).decode(buf);
}

/**
 * 移除 HTML 标签，保留纯文本
 * @param {string} html
 * @returns {string}
 */
function stripHtml(html) {
  return html
    .replace(/<br\s*\/?>/gi, "\n")
    .replace(/<\/p>/gi, "\n")
    .replace(/<[^>]+>/g, " ")
    .replace(/&amp;/g, "&")
    .replace(/&lt;/g, "<")
    .replace(/&gt;/g, ">")
    .replace(/&nbsp;/g, " ")
    .replace(/[ \t]+/g, " ");
}

/**
 * 从邮件原始文本中提取 6 位数字验证码
 * 优先在关键词上下文附近查找，避免误取邮件中其他数字
 * @param {string} raw
 * @returns {string|null}
 */
function extractOtp(raw) {
  // 方法一：关键词上下文匹配（最高优先级）
  // 在 code/verify/OTP 等关键词后面 200 字符内查找独立的 6 位数字
  const contextPatterns = [
    /(?:verification|verify|your\s+code|one.time|otp|passcode|authentication\s+code|enter\s+(?:the\s+)?code)[^\d]{0,80}(?<!\d)(\d{6})(?!\d)/iy,
    /(?<!\d)(\d{6})(?!\d)[^\d]{0,80}(?:is\s+your|to\s+verify|to\s+confirm|expires)/iy,
  ];
  for (const re of contextPatterns) {
    const m = raw.match(re);
    if (m) {
      const code = m[1] || m[2];
      if (code) return code;
    }
  }

  // 方法二：标准连续 6 位独立数字（前后无其他数字）
  const m1 = raw.match(/(?<!\d)(\d{6})(?!\d)/);
  if (m1) return m1[1];

  // 方法三：带空格的 6 位数字（如 "1 2 3 4 5 6" 或 "123 456"）
  const m2 = raw.match(/\b(\d{3})\s+(\d{3})\b/);
  if (m2) return m2[1] + m2[2];

  const m3 = raw.match(/(\d\s+){5}\d/);
  if (m3) {
    const candidate = m3[0].replace(/\s+/g, "");
    if (/^\d{6}$/.test(candidate)) return candidate;
  }

  return null;
}


/**
 * 从 MIME 邮件原文中提取可读文本（正文）：
 * 1. 找到头部与正文分隔空行
 * 2. 检测 Content-Transfer-Encoding，对 base64 部分进行解码
 * 3. 返回拼接后的所有文本段落
 * @param {string} rawText
 * @returns {string}
 */
function extractBodyText(rawText) {
  const texts = [];

  // 找所有 MIME 部分（包括单体邮件正文）
  // 用分隔符 \r\n\r\n 或 \n\n 找头部结束
  const parts = rawText.split(/(?:\r?\n){2,}/);

  let currentEncoding = "7bit";
  let inHeader = true;

  for (const part of parts) {
    // 判断是否是 MIME 头部块（含有 Content-Type / Content-Transfer-Encoding 等）
    const isHeader = /^[\w\-]+:/m.test(part) && !/\s{10}/.test(part.slice(0, 30));
    if (isHeader) {
      // 提取 Content-Transfer-Encoding
      const encMatch = part.match(/Content-Transfer-Encoding:\s*(\S+)/i);
      if (encMatch) currentEncoding = encMatch[1].toLowerCase().trim();
      inHeader = false;
      continue;
    }

    // 不是头部，当作内容来处理
    let text = part;
    if (currentEncoding === "base64") {
      try {
        // 清理非 base64 字符后解码
        const cleanB64 = part.replace(/[^A-Za-z0-9+/=\r\n]/g, "").replace(/\r?\n/g, "");
        const binary = atob(cleanB64);
        text = decodeURIComponent(escape(binary));
      } catch (e) {
        text = part; // 解码失败则原样使用
      }
      currentEncoding = "7bit"; // 重置
    } else if (currentEncoding === "quoted-printable") {
      text = part
        .replace(/=\r?\n/g, "")
        .replace(/=([0-9A-Fa-f]{2})/g, (_, h) => String.fromCharCode(parseInt(h, 16)));
      currentEncoding = "7bit";
    }
    texts.push(text);
  }

  return texts.join("\n");
}

// ========== 邮件事件处理器 ==========

/**
 * 处理 Cloudflare Email Worker 的 email 事件。
 * 将收件人地址作为 KV key，提取的验证码作为 value 存入 KV。
 */
async function handleEmail(event, env) {
  const toAddress = (event.to || "").toLowerCase().trim();
  if (!toAddress) {
    console.log("[email] 收件人地址为空，跳过");
    return;
  }

  // 读取原始邮件内容（Cloudflare 提供 ReadableStream）
  let rawText = "";
  try {
    rawText = await streamToText(event.raw);
  } catch (e) {
    console.log("[email] 读取邮件内容失败:", e);
    return;
  }

  // 提取发件人（用于日志）
  const fromMatch = rawText.match(/^From:\s*(.+)$/im);
  const from = fromMatch ? fromMatch[1].trim() : "(unknown)";
  console.log(`[email] from=${from} to=${toAddress}`);

  // 解码邮件正文（MIME 解析 + base64 / quoted-printable 解码）
  const bodyText = extractBodyText(rawText);
  // 去除 HTML 标签得到纯文本
  const plainText = stripHtml(bodyText);
  // 组合：解码后正文 + 原始邮件（保底）
  const fullBlob = plainText + "\n" + bodyText + "\n" + rawText;

  const code = extractOtp(fullBlob);
  // 调试：将邮件纯文本前 600 字符存入 KV（TTL 60s），方便排查提取结果
  try {
    const debugKey = `debug:${toAddress}`;
    const debugVal = JSON.stringify({ code, preview: plainText.slice(0, 600) });
    await env.OTP_STORE.put(debugKey, debugVal, { expirationTtl: 60 });
  } catch (_) {}

  if (!code) {
    console.log("[email] 未找到验证码，邮件预览:", fullBlob.slice(0, 300));
    return;
  }


  console.log(`[email] 验证码=${code} to=${toAddress}`);

  // 存入 KV，key 格式 "otp:{email}"，10 分钟 TTL
  const kvKey = `otp:${toAddress}`;
  try {
    await env.OTP_STORE.put(kvKey, code, { expirationTtl: 600 });
    console.log(`[email] 验证码已写入 KV: ${kvKey} = ${code}`);
  } catch (e) {
    console.log("[email] 写入 KV 失败:", e);
  }
}

// ========== HTTP 查询接口 ==========

/**
 * 处理 HTTP 请求：GET /code?email=xxx
 * 返回 JSON: { "code": "123456" } 或 { "code": null }
 * 成功返回后删除 KV 中的值（单次消费）
 */
async function handleFetch(request, env) {
  const url = new URL(request.url);

  // 健康检查
  if (url.pathname === "/health") {
    return new Response(JSON.stringify({ ok: true }), {
      headers: { "Content-Type": "application/json" },
    });
  }

  // 只处理 /code 或 /debug 路径
  if (url.pathname !== "/code" && url.pathname !== "/debug") {
    return new Response("Not Found", { status: 404 });
  }

  // API Key 鉴权
  const authHeader = request.headers.get("Authorization") || "";
  const token = authHeader.startsWith("Bearer ") ? authHeader.slice(7) : "";
  const expectedKey = env.WORKER_API_KEY || "";
  if (!expectedKey || token !== expectedKey) {
    return new Response(JSON.stringify({ error: "Unauthorized" }), {
      status: 401,
      headers: { "Content-Type": "application/json" },
    });
  }

  const email = (url.searchParams.get("email") || "").toLowerCase().trim();
  if (!email) {
    return new Response(JSON.stringify({ error: "email param required" }), {
      status: 400,
      headers: { "Content-Type": "application/json" },
    });
  }

  // /debug 接口：返回调试信息（邮件预览 + 提取的 code）
  if (url.pathname === "/debug") {
    const debugKey = `debug:${email}`;
    let dbg = null;
    try { dbg = await env.OTP_STORE.get(debugKey); } catch (_) {}
    return new Response(dbg || JSON.stringify({ error: "no debug data" }), {
      headers: { "Content-Type": "application/json" },
    });
  }

  const kvKey = `otp:${email}`;
  let code = null;
  try {
    code = await env.OTP_STORE.get(kvKey);
    if (code) {
      // 读取后立即删除，避免重复使用
      await env.OTP_STORE.delete(kvKey);
      console.log(`[fetch] 已返回并删除 KV: ${kvKey} = ${code}`);
    }
  } catch (e) {
    console.log("[fetch] 读取 KV 失败:", e);
  }

  return new Response(JSON.stringify({ code: code || null }), {
    headers: { "Content-Type": "application/json" },
  });
}

// ========== Worker 导出入口 ==========

export default {
  /**
   * HTTP 请求入口（GET /code?email=xxx 等）
   */
  async fetch(request, env, ctx) {
    return handleFetch(request, env);
  },

  /**
   * Email Worker 入口（Cloudflare Email Routing 触发）
   */
  async email(event, env, ctx) {
    ctx.waitUntil(handleEmail(event, env));
  },
};
