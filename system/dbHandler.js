// system/dbHandler.js
"use strict";

const crypto = require("crypto");
const { Database } = require("./database");

/* ============================================================
 *  HELPERS
 * ============================================================ */
function sha256(s) {
  return crypto.createHash("sha256").update(String(s)).digest("hex");
}
function genKeyTable() {
  return crypto.randomBytes(32).toString("hex");
}
function genTempToken() {
  return "otp_" + crypto.randomBytes(24).toString("hex");
}
function genOtp2Digit() {
  return String(Math.floor(Math.random() * 100)).padStart(2, "0");
}

function publicUser(row) {
  if (!row) return null;
  const { key_table, password, ...rest } = row;
  return rest;
}
function publicRow(row) {
  if (!row) return null;
  const { key_table, ...rest } = row;
  return rest;
}

/* ============================================================
 *  VALIDATORS
 * ============================================================ */
const SAFE_IDENT = /^[a-zA-Z_][a-zA-Z0-9_]*$/;
const SAFE_EMAIL = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
const SAFE_KEY   = /^[a-f0-9]{64}$/;

function assertSafeString(v, name, { min = 1, max = 255, allowEmpty = false } = {}) {
  if (v === undefined || v === null) {
    if (allowEmpty) return "";
    throw new Error(`${name} không được để trống`);
  }
  const t = String(v).trim();
  if (!allowEmpty && t.length < min) throw new Error(`${name} quá ngắn (min ${min})`);
  if (t.length > max) throw new Error(`${name} quá dài (max ${max})`);
  return t;
}
function assertPositiveInt(v, name) {
  const n = Number(v);
  if (!Number.isInteger(n) || n <= 0 || n > Number.MAX_SAFE_INTEGER) {
    throw new Error(`${name} phải là số nguyên dương`);
  }
  return n;
}
function assertEmail(v) {
  const t = String(v).trim().toLowerCase();
  if (!SAFE_EMAIL.test(t) || t.length > 50) throw new Error("Email không hợp lệ");
  return t;
}
function assertSafeIdent(v, name) {
  if (typeof v !== "string" || !SAFE_IDENT.test(v)) throw new Error(`${name} không hợp lệ`);
  return v;
}
function assertKeyTable(v) {
  if (typeof v !== "string" || !SAFE_KEY.test(v)) {
    throw new Error("key_table không hợp lệ (64 hex)");
  }
  return v;
}
function assertActive01(v, name = "active") {
  const a = String(v);
  if (a !== "0" && a !== "1") throw new Error(`${name} chỉ nhận '0' hoặc '1'`);
  return a;
}

const ALLOWED_USER_SORT    = new Set(["id", "username", "email", "active"]);
const ALLOWED_PROJECT_SORT = new Set(["id", "name", "status", "created_at", "update_at"]);
const ALLOWED_COMMENT_SORT = new Set(["id", "created_at", "update_at"]);
const ALLOWED_ORDER        = new Set(["ASC", "DESC"]);

/* ============================================================
 *  SEED
 * ============================================================ */
const SAMPLE_USERS = [
  { username: "admin", password: "admin123", email: "admin@acdv.dev", avatar: "None", active: "1" },
  { username: "test",  password: "123456",   email: "test@acdv.dev",  avatar: "None", active: "1" },
];

/* ============================================================
 *  DB HANDLER
 * ============================================================ */
class DBHandler {
  constructor(db = new Database()) {
    this.db = db;
    this._ready = null;
  }

  async init() {
    if (!this._ready) {
      this._ready = (async () => {
        await this.db.connect();
        await this._migrate();
      })();
    }
    return this._ready;
  }

  /** Thêm cột `hidden` cho project/comment nếu chưa có (idempotent) */
  async _migrate() {
    try {
      const dbName = this.db.config.database;
      const cols = await this.db.query(
        "SELECT TABLE_NAME AS t, COLUMN_NAME AS c FROM information_schema.COLUMNS " +
        "WHERE TABLE_SCHEMA = ? AND TABLE_NAME IN ('UserProject','CommentProject')",
        [dbName]
      );
      const has = (t, c) => cols.some((x) => x.t === t && x.c === c);

      if (!has("UserProject", "hidden")) {
        await this.db.query("ALTER TABLE UserProject ADD COLUMN hidden TINYINT(1) NOT NULL DEFAULT 0");
        console.log("  + migrated: UserProject.hidden");
      }
      if (!has("CommentProject", "hidden")) {
        await this.db.query("ALTER TABLE CommentProject ADD COLUMN hidden TINYINT(1) NOT NULL DEFAULT 0");
        console.log("  + migrated: CommentProject.hidden");
      }
    } catch (e) {
      console.warn("[migrate] warning:", e.message);
    }
  }

  /* ============================================================
   *  USER
   * ============================================================ */
  async getUserInternal(id) {
    await this.init();
    const safeId = assertPositiveInt(id, "id");
    const rows = await this.db.query(
      "SELECT id, username, password, avatar, email, `key_table`, token, active FROM `user` WHERE id = ? LIMIT 1",
      [safeId]
    );
    return rows[0] || null;
  }

  async getUser(id) {
    return publicUser(await this.getUserInternal(id));
  }

  async getUserByUsername(username) {
    await this.init();
    const safe = assertSafeString(username, "username", { min: 1, max: 50 });
    const rows = await this.db.query(
      "SELECT id, username, password, avatar, email, `key_table`, token, active FROM `user` WHERE username = ? LIMIT 1",
      [safe]
    );
    return publicUser(rows[0] || null);
  }

  async getUserByKeyTable(key_table) {
    await this.init();
    const safeKey = assertKeyTable(key_table);
    const rows = await this.db.query(
      "SELECT id, username, password, avatar, email, `key_table`, token, active FROM `user` WHERE `key_table` = ? LIMIT 1",
      [safeKey]
    );
    return rows[0] || null; // internal (có key_table + password)
  }

  /** key_table server tự sinh — không nhận từ ngoài */
  async createUser({ username, password, email = "None", avatar = "None", token = "None", active = "0" }) {
    await this.init();

    const u  = assertSafeString(username, "username", { min: 1, max: 50 });
    const pw = assertSafeString(password, "password", { min: 1, max: 255 });
    const e  = assertSafeString(email,    "email",    { min: 1, max: 50 });
    const av = assertSafeString(avatar,   "avatar",   { min: 1, max: 255 });
    const t  = assertSafeString(token,    "token",    { min: 1, max: 255 });
    const ac = assertActive01(active);

    const k = genKeyTable();

    if (await this.getUserByUsername(u)) throw new Error("Username đã tồn tại");
    if (e !== "None" && e.includes("@")) {
      const rows = await this.db.query("SELECT id FROM `user` WHERE email = ? LIMIT 1", [e]);
      if (rows.length) throw new Error("Email đã tồn tại");
    }

    const hashed = sha256(pw);
    const result = await this.db.query(
      "INSERT INTO `user` (username, password, avatar, email, `key_table`, token, active) VALUES (?, ?, ?, ?, ?, ?, ?)",
      [u, hashed, av, e, k, t, ac]
    );
    return this.getUser(Number(result.insertId));
  }

  async updateUser(id, patch = {}) {
    await this.init();
    const safeId = assertPositiveInt(id, "id");

    const sets = [];
    const params = [];
    if (patch.username !== undefined) { sets.push("username = ?"); params.push(assertSafeString(patch.username, "username", { min: 1, max: 50 })); }
    if (patch.password !== undefined) { sets.push("password = ?"); params.push(sha256(assertSafeString(patch.password, "password", { min: 1, max: 255 }))); }
    if (patch.avatar   !== undefined) { sets.push("avatar = ?");   params.push(assertSafeString(patch.avatar, "avatar", { min: 1, max: 255 })); }
    if (patch.email    !== undefined) { sets.push("email = ?");    params.push(assertSafeString(patch.email, "email", { min: 1, max: 50 })); }
    if (patch.token    !== undefined) { sets.push("token = ?");    params.push(assertSafeString(patch.token, "token", { min: 1, max: 255 })); }
    if (patch.active   !== undefined) { sets.push("active = ?");   params.push(assertActive01(patch.active)); }
    // ❌ key_table không cho update

    if (!sets.length) throw new Error("Không có trường nào để cập nhật");
    params.push(safeId);

    await this.db.query(`UPDATE \`user\` SET ${sets.join(", ")} WHERE id = ?`, params);
    return this.getUser(safeId);
  }

  /** ❌ Không ai được xóa user (kể cả admin) — route sẽ 403 */
  // (Giữ method cho internal seed/cleanup nếu cần, nhưng route không expose)

  async verifyLogin(identifier, password) {
    await this.init();
    const safeId = assertSafeString(identifier, "identifier", { min: 1, max: 50 });
    const hashed = sha256(assertSafeString(password, "password", { min: 1, max: 255 }));

    const rows = await this.db.query(
      "SELECT id, username, password, avatar, email, `key_table`, token, active FROM `user` WHERE username = ? OR email = ? LIMIT 1",
      [safeId, safeId]
    );
    const user = rows[0];
    if (!user || user.password !== hashed) return null;
    return publicUser(user);
  }

  /** Verify password của chính user (dùng cho request OTP) */
  async verifyPassword(id, password) {
    await this.init();
    const safeId = assertPositiveInt(id, "id");
    const hashed = sha256(assertSafeString(password, "password", { min: 1, max: 255 }));
    const rows = await this.db.query("SELECT id FROM `user` WHERE id = ? AND password = ? LIMIT 1", [safeId, hashed]);
    return rows.length > 0;
  }

  /* ============================================================
   *  PROFILE — chỉ upsert & get (KHÔNG xóa qua API)
   * ============================================================ */
  async getProfile(key_table) {
    await this.init();
    const k = assertKeyTable(key_table);
    const rows = await this.db.query(
      "SELECT id, name, LastName, Avatar, Location, phone, `key_table` FROM UserProfile WHERE `key_table` = ? LIMIT 1",
      [k]
    );
    return publicRow(rows[0] || null);
  }

  async upsertProfile(key_table, data = {}) {
    await this.init();
    const k = assertKeyTable(key_table);
    const existing = await this.getProfile(k);

    const FIELDS = [
      ["name", 255], ["LastName", 255], ["Avatar", 255], ["Location", 255], ["phone", 11],
    ];
    const values = {};
    for (const [f, max] of FIELDS) {
      if (data[f] !== undefined) values[f] = assertSafeString(data[f], f, { min: 0, max, allowEmpty: true });
      else if (existing) values[f] = existing[f] ?? "";
      else values[f] = "";
    }

    if (existing) {
      await this.db.query(
        "UPDATE UserProfile SET name=?, LastName=?, Avatar=?, Location=?, phone=? WHERE `key_table`=?",
        [values.name, values.LastName, values.Avatar, values.Location, values.phone, k]
      );
    } else {
      await this.db.query(
        "INSERT INTO UserProfile (name, LastName, Avatar, Location, phone, `key_table`) VALUES (?, ?, ?, ?, ?, ?)",
        [values.name, values.LastName, values.Avatar, values.Location, values.phone, k]
      );
    }
    return this.getProfile(k);
  }

  /* ============================================================
   *  PROJECT
   * ============================================================ */
  async getProject(id) {
    await this.init();
    const safeId = assertPositiveInt(id, "id");
    const rows = await this.db.query(
      "SELECT id, `key_table`, name, image, description, technologies, status, hidden, created_at, update_at " +
      "FROM UserProject WHERE id = ? AND hidden = 0 LIMIT 1",
      [safeId]
    );
    return publicRow(rows[0] || null);
  }

  /** Internal — trả full row (có key_table + hidden) để check owner/admin */
  async getProjectInternal(id) {
    await this.init();
    const safeId = assertPositiveInt(id, "id");
    const rows = await this.db.query(
      "SELECT id, `key_table`, name, image, description, technologies, status, hidden, created_at, update_at " +
      "FROM UserProject WHERE id = ? LIMIT 1",
      [safeId]
    );
    return rows[0] || null;
  }

  async listProjects({ page = 1, limit = 20, sort = "id", order = "DESC", q = null, status = null, key_table = null, includeHidden = false } = {}) {
    await this.init();

    const p = assertPositiveInt(page, "page");
    const l = Math.min(100, assertPositiveInt(limit, "limit"));
    const col = assertSafeIdent(sort, "sort");
    if (!ALLOWED_PROJECT_SORT.has(col)) throw new Error(`sort chỉ cho phép: ${[...ALLOWED_PROJECT_SORT].join(", ")}`);
    const dir = String(order).toUpperCase();
    if (!ALLOWED_ORDER.has(dir)) throw new Error("order chỉ cho phép ASC / DESC");
    const offset = (p - 1) * l;

    let sql = "SELECT id, `key_table`, name, image, description, technologies, status, hidden, created_at, update_at FROM UserProject WHERE 1=1";
    const params = [];
    if (!includeHidden) sql += " AND hidden = 0";
    if (key_table) { sql += " AND `key_table` = ?"; params.push(assertKeyTable(key_table)); }
    if (status)    { sql += " AND status = ?";     params.push(assertSafeString(status, "status", { min: 1, max: 500 })); }
    if (q) {
      const kw = assertSafeString(q, "q", { min: 1, max: 100 });
      sql += " AND (name LIKE ? OR description LIKE ?)";
      params.push(`%${kw}%`, `%${kw}%`);
    }
    sql += ` ORDER BY ${col} ${dir} LIMIT ${l} OFFSET ${offset}`;
    const rows = await this.db.query(sql, params);

    let countSql = "SELECT COUNT(*) AS total FROM UserProject WHERE 1=1";
    const cParams = [];
    if (!includeHidden) countSql += " AND hidden = 0";
    if (key_table) { countSql += " AND `key_table` = ?"; cParams.push(key_table); }
    if (status)    { countSql += " AND status = ?";     cParams.push(status); }
    if (q)         { countSql += " AND (name LIKE ? OR description LIKE ?)"; cParams.push(`%${q}%`, `%${q}%`); }
    const [{ total }] = await this.db.query(countSql, cParams);

    return {
      items: rows.map(publicRow),
      page: p, limit: l,
      total: Number(total),
      totalPages: Math.ceil(Number(total) / l),
    };
  }

  async createProject({ key_table, name, image = "None", description = "", technologies = "", status = "" }) {
    await this.init();
    const k  = assertKeyTable(key_table);
    const n  = assertSafeString(name, "name", { min: 1, max: 60 });
    const im = assertSafeString(image, "image", { min: 1, max: 255 });
    const de = assertSafeString(description, "description", { min: 0, max: 500, allowEmpty: true });
    const te = assertSafeString(technologies, "technologies", { min: 0, max: 500, allowEmpty: true });
    const st = assertSafeString(status, "status", { min: 0, max: 500, allowEmpty: true });

    const result = await this.db.query(
      "INSERT INTO UserProject (`key_table`, name, image, description, technologies, status, hidden, created_at, update_at) " +
      "VALUES (?, ?, ?, ?, ?, ?, 0, NOW(), NOW())",
      [k, n, im, de, te, st]
    );
    return this.getProject(Number(result.insertId));
  }

  async updateProject(id, patch = {}) {
    await this.init();
    const safeId = assertPositiveInt(id, "id");

    const sets = [];
    const params = [];
    if (patch.name         !== undefined) { sets.push("name = ?");         params.push(assertSafeString(patch.name, "name", { min: 1, max: 60 })); }
    if (patch.image        !== undefined) { sets.push("image = ?");        params.push(assertSafeString(patch.image, "image", { min: 1, max: 255 })); }
    if (patch.description  !== undefined) { sets.push("description = ?");  params.push(assertSafeString(patch.description, "description", { min: 0, max: 500, allowEmpty: true })); }
    if (patch.technologies !== undefined) { sets.push("technologies = ?"); params.push(assertSafeString(patch.technologies, "technologies", { min: 0, max: 500, allowEmpty: true })); }
    if (patch.status       !== undefined) { sets.push("status = ?");       params.push(assertSafeString(patch.status, "status", { min: 0, max: 500, allowEmpty: true })); }

    if (!sets.length) throw new Error("Không có trường nào để cập nhật");
    sets.push("update_at = NOW()");
    params.push(safeId);

    await this.db.query(`UPDATE UserProject SET ${sets.join(", ")} WHERE id = ?`, params);
    return this.getProjectInternal(safeId);
  }

  /** HARD DELETE — chỉ gọi khi route đã verify owner */
  async deleteProject(id) {
    await this.init();
    const safeId = assertPositiveInt(id, "id");
    const r = await this.db.query("DELETE FROM UserProject WHERE id = ?", [safeId]);
    return r.affectedRows > 0;
  }

  /** SOFT HIDE — chỉ admin gọi */
  async hideProject(id, hidden = 1) {
    await this.init();
    const safeId = assertPositiveInt(id, "id");
    const h = hidden ? 1 : 0;
    const r = await this.db.query("UPDATE UserProject SET hidden = ?, update_at = NOW() WHERE id = ?", [h, safeId]);
    return r.affectedRows > 0;
  }

  /* ============================================================
   *  COMMENT
   * ============================================================ */
  async getComment(id) {
    await this.init();
    const safeId = assertPositiveInt(id, "id");
    const rows = await this.db.query(
      "SELECT id, `key_table`, idProject, context, hidden, created_at, update_at FROM CommentProject WHERE id = ? AND hidden = 0 LIMIT 1",
      [safeId]
    );
    return publicRow(rows[0] || null);
  }

  async getCommentInternal(id) {
    await this.init();
    const safeId = assertPositiveInt(id, "id");
    const rows = await this.db.query(
      "SELECT id, `key_table`, idProject, context, hidden, created_at, update_at FROM CommentProject WHERE id = ? LIMIT 1",
      [safeId]
    );
    return rows[0] || null;
  }

  async listComments({ idProject = null, key_table = null, page = 1, limit = 20, sort = "id", order = "DESC", includeHidden = false } = {}) {
    await this.init();
    const p = assertPositiveInt(page, "page");
    const l = Math.min(100, assertPositiveInt(limit, "limit"));
    const col = assertSafeIdent(sort, "sort");
    if (!ALLOWED_COMMENT_SORT.has(col)) throw new Error(`sort chỉ cho phép: ${[...ALLOWED_COMMENT_SORT].join(", ")}`);
    const dir = String(order).toUpperCase();
    if (!ALLOWED_ORDER.has(dir)) throw new Error("order chỉ cho phép ASC / DESC");
    const offset = (p - 1) * l;

    let sql = "SELECT id, `key_table`, idProject, context, hidden, created_at, update_at FROM CommentProject WHERE 1=1";
    const params = [];
    if (!includeHidden) sql += " AND hidden = 0";
    if (idProject) { sql += " AND idProject = ?"; params.push(assertPositiveInt(idProject, "idProject")); }
    if (key_table) { sql += " AND `key_table` = ?"; params.push(assertKeyTable(key_table)); }
    sql += ` ORDER BY ${col} ${dir} LIMIT ${l} OFFSET ${offset}`;
    const rows = await this.db.query(sql, params);

    let countSql = "SELECT COUNT(*) AS total FROM CommentProject WHERE 1=1";
    const cParams = [];
    if (!includeHidden) countSql += " AND hidden = 0";
    if (idProject) { countSql += " AND idProject = ?"; cParams.push(Number(idProject)); }
    if (key_table) { countSql += " AND `key_table` = ?"; cParams.push(key_table); }
    const [{ total }] = await this.db.query(countSql, cParams);

    return {
      items: rows.map(publicRow),
      page: p, limit: l,
      total: Number(total),
      totalPages: Math.ceil(Number(total) / l),
    };
  }

  async createComment({ key_table, idProject, context }) {
    await this.init();
    const k  = assertKeyTable(key_table);
    const ip = assertPositiveInt(idProject, "idProject");
    const ct = assertSafeString(context, "context", { min: 1, max: 100 });

    const result = await this.db.query(
      "INSERT INTO CommentProject (`key_table`, idProject, context, hidden, created_at, update_at) VALUES (?, ?, ?, 0, NOW(), NOW())",
      [k, ip, ct]
    );
    return this.getCommentInternal(Number(result.insertId));
  }

  async updateComment(id, { context }) {
    await this.init();
    const safeId = assertPositiveInt(id, "id");
    const ct = assertSafeString(context, "context", { min: 1, max: 100 });
    await this.db.query("UPDATE CommentProject SET context = ?, update_at = NOW() WHERE id = ?", [ct, safeId]);
    return this.getCommentInternal(safeId);
  }

  /** HARD DELETE — chỉ tác giả comment */
  async deleteComment(id) {
    await this.init();
    const safeId = assertPositiveInt(id, "id");
    const r = await this.db.query("DELETE FROM CommentProject WHERE id = ?", [safeId]);
    return r.affectedRows > 0;
  }

  /** SOFT HIDE — chỉ chủ project (hoặc admin) */
  async hideComment(id, hidden = 1) {
    await this.init();
    const safeId = assertPositiveInt(id, "id");
    const h = hidden ? 1 : 0;
    const r = await this.db.query("UPDATE CommentProject SET hidden = ?, update_at = NOW() WHERE id = ?", [h, safeId]);
    return r.affectedRows > 0;
  }

  /* ============================================================
   *  OTP — request cần password, verify dùng temp token
   * ============================================================ */

  /**
   * Sinh OTP mới: cần verify password trước.
   * Trả về { id, otp, token, expiresIn } — token là tạm, tách khỏi session.
   */
  async requestOTP(userId, password, ttlMs = 5 * 60 * 1000) {
    await this.init();
    const safeId = assertPositiveInt(userId, "userId");

    // 1) Verify password
    const ok = await this.verifyPassword(safeId, password);
    if (!ok) throw new Error("Mật khẩu không đúng");

    // 2) Lấy user để có key_table
    const user = await this.getUserInternal(safeId);
    if (!user) throw new Error("Không tìm thấy user");
    const k = user.key_table;

    // 3) Vô hiệu OTP cũ
    await this.db.query("UPDATE OTPAuthUser SET active = 0 WHERE `key_table` = ?", [k]);

    // 4) Sinh OTP + temp token
    const otp = genOtp2Digit();
    const tempToken = genTempToken();

    const result = await this.db.query(
      "INSERT INTO OTPAuthUser (active, OTP, token, `key_table`, CreatDateTimes) VALUES (1, ?, ?, ?, NOW())",
      [otp, tempToken, k]
    );

    return {
      id: Number(result.insertId),
      otp,                 // ⚠️ thực tế gửi qua email/SMS — demo trả về luôn
      token: tempToken,    // 🔑 Temp token riêng cho OTP
      expiresIn: Math.floor(ttlMs / 1000),
    };
  }

  /** Verify OTP bằng temp token — KHÔNG cần session login */
  async verifyOTPByToken(tempToken, otp) {
    await this.init();
    const t = assertSafeString(tempToken, "token", { min: 1, max: 256 });
    const o = assertSafeString(otp, "otp", { min: 1, max: 2 });

    const rows = await this.db.query(
      "SELECT id, `key_table` FROM OTPAuthUser WHERE token = ? AND OTP = ? AND active = 1 ORDER BY id DESC LIMIT 1",
      [t, o]
    );
    if (!rows.length) return { ok: false, message: "OTP hoặc token không hợp lệ / đã dùng" };

    await this.db.query("UPDATE OTPAuthUser SET active = 0 WHERE id = ?", [rows[0].id]);
    return { ok: true, id: rows[0].id };
  }

  async getOTP(id) {
    await this.init();
    const safeId = assertPositiveInt(id, "id");
    const rows = await this.db.query(
      "SELECT id, active, OTP, token, `key_table`, CreatDateTimes FROM OTPAuthUser WHERE id = ? LIMIT 1",
      [safeId]
    );
    return publicRow(rows[0] || null);
  }

  async getOTPInternal(id) {
    await this.init();
    const safeId = assertPositiveInt(id, "id");
    const rows = await this.db.query(
      "SELECT id, active, OTP, token, `key_table`, CreatDateTimes FROM OTPAuthUser WHERE id = ? LIMIT 1",
      [safeId]
    );
    return rows[0] || null;
  }

  async listOTPByKey(key_table) {
    await this.init();
    const k = assertKeyTable(key_table);
    const rows = await this.db.query(
      "SELECT id, active, OTP, token, `key_table`, CreatDateTimes FROM OTPAuthUser WHERE `key_table` = ? ORDER BY id DESC LIMIT 50",
      [k]
    );
    return rows.map(publicRow);
  }

  async deleteOTP(id) {
    await this.init();
    const safeId = assertPositiveInt(id, "id");
    const r = await this.db.query("DELETE FROM OTPAuthUser WHERE id = ?", [safeId]);
    return r.affectedRows > 0;
  }

  /* ============================================================
   *  SEED
   * ============================================================ */
  async seedSampleData(list = SAMPLE_USERS) {
    await this.init();
    let inserted = 0;

    for (const u of list) {
      const existed = await this.getUserByUsername(u.username).catch(() => null);
      if (existed) continue;

      const pubU = await this.createUser({ ...u, token: "None" });
      const fullU = await this.getUserInternal(pubU.id);

      await this.upsertProfile(fullU.key_table, {
        name: u.username, LastName: "Demo",
        Avatar: "None", Location: "Vietnam", phone: "0000000000",
      });

      await this.createProject({
        key_table: fullU.key_table,
        name: `Project của ${u.username}`,
        image: "None",
        description: "Project mẫu seed tự động",
        technologies: JSON.stringify(["Node.js", "MariaDB", "ESP32"]),
        status: "Completed",
      });

      inserted++;
      console.log(`  + seeded user: ${u.username}`);
    }
    console.log(`🌱 Seed xong. Thêm mới ${inserted} user.`);
    return { inserted };
  }

  async close() { await this.db.close(); }
}

module.exports = {
  DBHandler, SAMPLE_USERS,
  sha256, genKeyTable, genTempToken, genOtp2Digit,
  publicUser, publicRow,
};