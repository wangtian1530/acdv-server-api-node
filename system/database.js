// system/database.js
"use strict";

const mariadb = require("mariadb");
const config = require("../config");

class Database {
  /**
   * @param {object} cfg - cấu hình db (mặc định lấy từ config.js)
   */
  constructor(cfg = config.db) {
    this.config = cfg;
    this.pool = null;
  }

  /**
   * Khởi tạo pool + test kết nối
   */
  async connect() {
    if (this.pool) return this.pool;

    this.pool = mariadb.createPool({
      host: this.config.host,
      port: this.config.port,
      user: this.config.user,
      password: this.config.password,
      database: this.config.database,
      connectionLimit: this.config.connectionLimit,
      acquireTimeout: this.config.acquireTimeout,
      idleTimeout: this.config.idleTimeout,
      charset: this.config.charset,
      timezone: this.config.timezone,

      // ====== CHỐNG SQL INJECTION ======
      multipleStatements: false,   // không cho `; DROP TABLE ...`
      bigIntAsNumber: true,
      dateStrings: false,
      // =================================
    });

    // Test kết nối
    const conn = await this.pool.getConnection();
    try {
      await conn.ping();
      console.log(
        `✅ MariaDB connected → ${this.config.user}@${this.config.host}:${this.config.port}/${this.config.database}`
      );
    } finally {
      conn.release();
    }
    return this.pool;
  }

  /**
   * Query an toàn (dùng prepared statement với `?`)
   * @param {string} sql
   * @param {Array} params
   */
  async query(sql, params = []) {
    if (!this.pool) await this.connect();

    // Cảnh báo nếu thấy params rỗng mà SQL có `?` -> tránh lỗi injection do nối chuỗi
    if (/\?/.test(sql) && params.length === 0) {
      console.warn("[DB] SQL có placeholder '?' nhưng không truyền params!", sql);
    }

    let conn;
    try {
      conn = await this.pool.getConnection();
      const rows = await conn.query(sql, params);
      return rows;
    } finally {
      if (conn) conn.release();
    }
  }

  async execute(sql, params = []) {
    return this.query(sql, params);
  }

  /**
   * Transaction helper
   */
  async transaction(fn) {
    if (!this.pool) await this.connect();
    const conn = await this.pool.getConnection();
    try {
      await conn.beginTransaction();
      const result = await fn(conn);
      await conn.commit();
      return result;
    } catch (err) {
      await conn.rollback();
      throw err;
    } finally {
      conn.release();
    }
  }

  async close() {
    if (this.pool) {
      await this.pool.end();
      this.pool = null;
      console.log("🔌 MariaDB pool closed");
    }
  }
}

module.exports = { Database };