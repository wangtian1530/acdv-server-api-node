// config.js
"use strict";

const USE_PORT = false;

module.exports = {
  server: { port: Number(process.env.PORT) || 3000 },

  db: {
    enabled: true,
    host: process.env.DB_HOST || "acdv-database.acdv-teams.io.vn",
    ...(USE_PORT ? { port: Number(process.env.DB_PORT) || 3306 } : {}),
    user: process.env.DB_USER || "ACDV_Teams",
    password: process.env.DB_PASSWORD || "keyadminkali@Xy[",
    database: process.env.DB_NAME || "ACDV_Teams",
    connectionLimit: 10,
    acquireTimeout: 10000,
    idleTimeout: 60000,
    charset: "utf8mb4",
    timezone: "Z",
    multipleStatements: false,
  },

  security: {
    capacity: 1000,
    refillPerSec: 2,
    ttl: 60 * 60 * 1000,
    anonTtl: 10 * 60 * 1000,
    cookieName: "sid",
    headerName: "x-session-token",
    trustProxy: true,
    // 🔐 Danh sách admin (chỉ có quyền ẨN, không xóa)
    adminUsernames: ["admin"],
    // ⏱️ OTP sống 5 phút
    otpTtlMs: 5 * 60 * 1000,
  },

  seed: {
    enabled: process.env.SEED !== "false",
  },
};