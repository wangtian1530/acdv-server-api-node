// server.js
"use strict";

const http = require("http");
const Medthod = require("./system/method");
const { Security } = require("./system/security");
const { buildRouter } = require("./routes");
const config = require("./config");

// ============================================================
// 🔀 FACTORY — chọn backend theo cờ config.db.enabled
//    (thay cho require("./system") để khỏi phải tạo system/index.js)
// ============================================================
const { DBHandler } = require("./system/dbHandler");
const { MemoryHandler } = require("./system/memoryHandler");

function createDbHandler() {
  if (config.db.enabled) {
    console.log("🗄️  DB mode: MariaDB");
    return new DBHandler();
  }
  console.log("🧠 DB mode: In-Memory (không cần MariaDB)");
  return new MemoryHandler();
}

const PORT = config.server.port;

// ============================================================
// TIỆN ÍCH CHUNG
// ============================================================
function sendJSON(res, statusCode, data) {
  res.writeHead(statusCode, {
    "Content-Type": "application/json; charset=utf-8",
  });
  res.end(JSON.stringify(data));
}

function readBody(req) {
  return new Promise((resolve, reject) => {
    let raw = "";
    req.on("data", (chunk) => {
      raw += chunk.toString();
      if (raw.length > 1e6) {
        reject(new Error("Payload quá lớn"));
        req.destroy();
      }
    });
    req.on("end", () => {
      if (!raw) return resolve({});
      try {
        resolve(JSON.parse(raw));
      } catch {
        reject(new Error("JSON không hợp lệ"));
      }
    });
    req.on("error", reject);
  });
}

function parseQuery(url) {
  const idx = url.indexOf("?");
  if (idx === -1) return {};
  const params = new URLSearchParams(url.slice(idx + 1));
  const out = {};
  for (const [k, v] of params.entries()) out[k] = v;
  return out;
}

function summarizeBody(body) {
  if (!body || typeof body !== "object") return {};
  const redactedKeys = new Set(["password", "otp", "token", "secret", "authorization"]);
  return Object.fromEntries(
    Object.entries(body).map(([k, v]) => [
      k,
      redactedKeys.has(k) ? "[hidden]" : (typeof v === "object" ? "[object]" : String(v)),
    ])
  );
}

// ============================================================
// DATABASE — tự động chọn MariaDB / In-Memory
// ============================================================
const db = createDbHandler();

// ============================================================
// SECURITY
// ============================================================
const security = new Security(config.security);
const securityMiddleware = security.middleware();
const requireAuth = security.requireAuth();

// ============================================================
// ROUTER
// ============================================================
const router = buildRouter({ security, db, requireAuth });

// ============================================================
// HTTP SERVER
// ============================================================
const server = http.createServer(async (req, res) => {
  // ---------- CORS ----------
  res.setHeader("Access-Control-Allow-Origin", "*");
  res.setHeader(
    "Access-Control-Allow-Methods",
    "GET, POST, PUT, DELETE, PATCH, OPTIONS"
  );
  res.setHeader(
    "Access-Control-Allow-Headers",
    "Content-Type, Authorization, X-Session-Token"
  );
  res.setHeader(
    "Access-Control-Expose-Headers",
    "X-Session-Token, X-RateLimit-Limit, X-RateLimit-Remaining"
  );
  res.setHeader("Access-Control-Allow-Credentials", "true");

  if (req.method === "OPTIONS") {
    res.writeHead(204);
    res.end();
    return;
  }

  const url = req.url;
  const pathOnly = url.split("?")[0];
  const query = parseQuery(url);

  // ---------- Body ----------
  let body = {};
  if (req.method === "POST" || req.method === "PUT" || req.method === "PATCH") {
    try {
      body = await readBody(req);
    } catch (err) {
      return sendJSON(res, 400, { status: "error", message: err.message });
    }
  }

  // ---------- Context ----------
  const ctx = {
    req,
    res,
    url,
    path: pathOnly,
    query,
    body,
    headers: req.headers,
    method: req.method,
  };

  console.log(
    `[${new Date().toISOString()}] ${req.method} ${pathOnly} query=${JSON.stringify(query)} body=${JSON.stringify(summarizeBody(body))}`
  );

  // ---------- SECURITY GATE ----------
  try {
    const blocked = await securityMiddleware(ctx);
    if (blocked) {
      console.log(`[${new Date().toISOString()}] ${req.method} ${pathOnly} => blocked ${blocked.status}`);
      return sendJSON(res, blocked.status, blocked.data);
    }
  } catch (err) {
    console.error("[SECURITY] middleware error:", err);
    return sendJSON(res, 500, {
      status: "error",
      message: "Lỗi hệ thống bảo mật",
    });
  }

  // ---------- ROUTER ----------
  try {
    const { status, data } = await router.handle(ctx);
    console.log(`[${new Date().toISOString()}] ${req.method} ${pathOnly} => ${status || 200}`);
    sendJSON(res, status || 200, data);
  } catch (err) {
    console.error("[ROUTER] error:", err);
    sendJSON(res, 500, { status: "error", message: "Lỗi xử lý request" });
  }
});

// ============================================================
// CLEANUP + BOOT
// ============================================================
if (typeof Medthod.cleanExpired === "function") {
  setInterval(() => Medthod.cleanExpired(60000), 60000).unref();
}

(async () => {
  try {
    await db.init();

    if (config.seed.enabled) {
      console.log("🌱 Seeding sample data...");
      await db.seedSampleData();
    }

    server.listen(PORT, () => {
      console.log(`🚀 Server: http://localhost:${PORT}`);
      console.log(`🗄️  Backend: ${config.db.enabled ? "MariaDB" : "In-Memory"}`);
      console.log(`🔐 Security: 1000 req/IP, +2 req/s, session binding ON`);
      console.log(`📦 Routes: routes/index.js`);
    });
  } catch (err) {
    console.error("❌ Khởi động thất bại:", err);
    process.exit(1);
  }
})();

// ============================================================
// GRACEFUL SHUTDOWN
// ============================================================
process.on("SIGINT", async () => {
  console.log("\n🛑 Đang tắt...");
  await db.close();
  process.exit(0);
});