// system/memoryHandler.js
"use strict";

const crypto = require("crypto");

function sha256(s) {
  return crypto.createHash("sha256").update(String(s)).digest("hex");
}
function genKeyTable()  { return crypto.randomBytes(32).toString("hex"); }
function genTempToken() { return "otp_" + crypto.randomBytes(24).toString("hex"); }
function genOtp2Digit() { return String(Math.floor(Math.random() * 100)).padStart(2, "0"); }

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
  if (!Number.isInteger(n) || n <= 0) throw new Error(`${name} phải là số nguyên dương`);
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
  if (typeof v !== "string" || !SAFE_KEY.test(v)) throw new Error("key_table không hợp lệ");
  return v;
}
function assertActive01(v, name = "active") {
  const a = String(v);
  if (a !== "0" && a !== "1") throw new Error(`${name} chỉ nhận '0' hoặc '1'`);
  return a;
}

const ALLOWED_PROJECT_SORT = new Set(["id", "name", "status", "created_at", "update_at"]);
const ALLOWED_COMMENT_SORT = new Set(["id", "created_at", "update_at"]);
const ALLOWED_ORDER        = new Set(["ASC", "DESC"]);

const SAMPLE_USERS = [
  { username: "admin", password: "admin123", email: "admin@acdv.dev", avatar: "None", active: "1" },
  { username: "test",  password: "123456",   email: "test@acdv.dev",  avatar: "None", active: "1" },
];

class MemoryHandler {
  constructor() {
    this.users    = [];
    this.profiles = [];
    this.projects = [];
    this.comments = [];
    this.otps     = [];
    this.seq = { user: 1, profile: 1, project: 1, comment: 1, otp: 1 };
  }
  async init() { return true; }
  _now() { return new Date(); }

  /* ---------- USER ---------- */
  async getUserInternal(id) {
    const n = assertPositiveInt(id, "id");
    const u = this.users.find((x) => x.id === n);
    return u ? { ...u } : null;
  }
  async getUser(id) { return publicUser(await this.getUserInternal(id)); }

  async getUserByUsername(username) {
    const u = assertSafeString(username, "username", { min: 1, max: 50 });
    const found = this.users.find((x) => x.username === u);
    return publicUser(found ? { ...found } : null);
  }
  async getUserByKeyTable(key_table) {
    const k = assertKeyTable(key_table);
    const u = this.users.find((x) => x.key_table === k);
    return u ? { ...u } : null;
  }

  async createUser({ username, password, email = "None", avatar = "None", token = "None", active = "0" }) {
    const u  = assertSafeString(username, "username", { min: 1, max: 50 });
    const pw = assertSafeString(password, "password", { min: 1, max: 255 });
    const e  = assertSafeString(email,    "email",    { min: 1, max: 50 });
    const av = assertSafeString(avatar,   "avatar",   { min: 1, max: 255 });
    const t  = assertSafeString(token,    "token",    { min: 1, max: 255 });
    const ac = assertActive01(active);
    const k  = genKeyTable();

    if (this.users.some((x) => x.username === u)) throw new Error("Username đã tồn tại");
    if (e !== "None" && e.includes("@") && this.users.some((x) => x.email === e)) throw new Error("Email đã tồn tại");

    const row = {
      id: this.seq.user++, username: u, password: sha256(pw),
      avatar: av, email: e, key_table: k, token: t, active: ac,
    };
    this.users.push(row);
    return this.getUser(row.id);
  }

  async updateUser(id, patch = {}) {
    const n = assertPositiveInt(id, "id");
    const idx = this.users.findIndex((x) => x.id === n);
    if (idx === -1) throw new Error("Không tìm thấy user");

    const next = { ...this.users[idx] };
    if (patch.username !== undefined) {
      const u = assertSafeString(patch.username, "username", { min: 1, max: 50 });
      if (this.users.some((x) => x.username === u && x.id !== n)) throw new Error("Username đã tồn tại");
      next.username = u;
    }
    if (patch.password !== undefined) next.password = sha256(assertSafeString(patch.password, "password", { min: 1, max: 255 }));
    if (patch.avatar   !== undefined) next.avatar   = assertSafeString(patch.avatar, "avatar", { min: 1, max: 255 });
    if (patch.email    !== undefined) next.email    = assertSafeString(patch.email, "email",   { min: 1, max: 50 });
    if (patch.token    !== undefined) next.token    = assertSafeString(patch.token, "token",   { min: 1, max: 255 });
    if (patch.active   !== undefined) next.active   = assertActive01(patch.active);

    this.users[idx] = next;
    return this.getUser(n);
  }

  async verifyLogin(identifier, password) {
    const id = assertSafeString(identifier, "identifier", { min: 1, max: 50 });
    const h = sha256(assertSafeString(password, "password", { min: 1, max: 255 }));
    const u = this.users.find((x) => (x.username === id || x.email === id) && x.password === h);
    return publicUser(u ? { ...u } : null);
  }

  async verifyPassword(id, password) {
    const n = assertPositiveInt(id, "id");
    const h = sha256(assertSafeString(password, "password", { min: 1, max: 255 }));
    const u = this.users.find((x) => x.id === n && x.password === h);
    return !!u;
  }

  /* ---------- PROFILE ---------- */
  async getProfile(key_table) {
    const k = assertKeyTable(key_table);
    const p = this.profiles.find((x) => x.key_table === k);
    return publicRow(p ? { ...p } : null);
  }
  async upsertProfile(key_table, data = {}) {
    const k = assertKeyTable(key_table);
    const existing = this.profiles.find((x) => x.key_table === k);
    const FIELDS = [["name", 255], ["LastName", 255], ["Avatar", 255], ["Location", 255], ["phone", 11]];
    const values = {};
    for (const [f, max] of FIELDS) {
      if (data[f] !== undefined) values[f] = assertSafeString(data[f], f, { min: 0, max, allowEmpty: true });
      else if (existing) values[f] = existing[f] ?? "";
      else values[f] = "";
    }
    if (existing) {
      Object.assign(existing, values);
      return publicRow({ ...existing });
    }
    const row = { id: this.seq.profile++, key_table: k, ...values };
    this.profiles.push(row);
    return publicRow({ ...row });
  }

  /* ---------- PROJECT ---------- */
  async getProject(id) {
    const n = assertPositiveInt(id, "id");
    const p = this.projects.find((x) => x.id === n && !x.hidden);
    return publicRow(p ? { ...p } : null);
  }
  async getProjectInternal(id) {
    const n = assertPositiveInt(id, "id");
    const p = this.projects.find((x) => x.id === n);
    return p ? { ...p } : null;
  }
  async listProjects({ page = 1, limit = 20, sort = "id", order = "DESC", q = null, status = null, key_table = null, includeHidden = false } = {}) {
    const p = assertPositiveInt(page, "page");
    const l = Math.min(100, assertPositiveInt(limit, "limit"));
    const col = assertSafeIdent(sort, "sort");
    if (!ALLOWED_PROJECT_SORT.has(col)) throw new Error(`sort chỉ cho phép: ${[...ALLOWED_PROJECT_SORT].join(", ")}`);
    const dir = String(order).toUpperCase();
    if (!ALLOWED_ORDER.has(dir)) throw new Error("order chỉ cho phép ASC / DESC");

    let list = this.projects.map((x) => ({ ...x }));
    if (!includeHidden) list = list.filter((x) => !x.hidden);
    if (key_table) { const k = assertKeyTable(key_table); list = list.filter((x) => x.key_table === k); }
    if (status)    { const s = assertSafeString(status, "status", { min: 1, max: 500 }); list = list.filter((x) => x.status === s); }
    if (q) {
      const kw = assertSafeString(q, "q", { min: 1, max: 100 }).toLowerCase();
      list = list.filter((x) => (x.name || "").toLowerCase().includes(kw) || (x.description || "").toLowerCase().includes(kw));
    }
    list.sort((a, b) => {
      const A = a[col], B = b[col];
      if (A == null) return 1;
      if (B == null) return -1;
      if (A instanceof Date && B instanceof Date) return dir === "ASC" ? A - B : B - A;
      if (typeof A === "number" && typeof B === "number") return dir === "ASC" ? A - B : B - A;
      const sa = String(A).toLowerCase(), sb = String(B).toLowerCase();
      if (sa < sb) return dir === "ASC" ? -1 : 1;
      if (sa > sb) return dir === "ASC" ? 1 : -1;
      return 0;
    });
    const total = list.length;
    const offset = (p - 1) * l;
    return {
      items: list.slice(offset, offset + l).map(publicRow),
      page: p, limit: l, total, totalPages: Math.ceil(total / l),
    };
  }
  async createProject({ key_table, name, image = "None", description = "", technologies = "", status = "" }) {
    const k = assertKeyTable(key_table);
    if (!this.users.some((x) => x.key_table === k)) throw new Error("key_table không tồn tại");
    const n  = assertSafeString(name, "name", { min: 1, max: 60 });
    const im = assertSafeString(image, "image", { min: 1, max: 255 });
    const de = assertSafeString(description, "description", { min: 0, max: 500, allowEmpty: true });
    const te = assertSafeString(technologies, "technologies", { min: 0, max: 500, allowEmpty: true });
    const st = assertSafeString(status, "status", { min: 0, max: 500, allowEmpty: true });

    const now = this._now();
    const row = {
      id: this.seq.project++, key_table: k, name: n, image: im,
      description: de, technologies: te, status: st, hidden: 0,
      created_at: now, update_at: now,
    };
    this.projects.push(row);
    return publicRow({ ...row });
  }
  async updateProject(id, patch = {}) {
    const n = assertPositiveInt(id, "id");
    const p = this.projects.find((x) => x.id === n);
    if (!p) throw new Error("Không tìm thấy project");
    if (patch.name         !== undefined) p.name         = assertSafeString(patch.name, "name", { min: 1, max: 60 });
    if (patch.image        !== undefined) p.image        = assertSafeString(patch.image, "image", { min: 1, max: 255 });
    if (patch.description  !== undefined) p.description  = assertSafeString(patch.description, "description", { min: 0, max: 500, allowEmpty: true });
    if (patch.technologies !== undefined) p.technologies = assertSafeString(patch.technologies, "technologies", { min: 0, max: 500, allowEmpty: true });
    if (patch.status       !== undefined) p.status       = assertSafeString(patch.status, "status", { min: 0, max: 500, allowEmpty: true });
    p.update_at = this._now();
    return { ...p };
  }
  async deleteProject(id) {
    const n = assertPositiveInt(id, "id");
    const i = this.projects.findIndex((x) => x.id === n);
    if (i === -1) return false;
    this.projects.splice(i, 1);
    this.comments = this.comments.filter((c) => c.idProject !== n);
    return true;
  }
  async hideProject(id, hidden = 1) {
    const n = assertPositiveInt(id, "id");
    const p = this.projects.find((x) => x.id === n);
    if (!p) return false;
    p.hidden = hidden ? 1 : 0;
    p.update_at = this._now();
    return true;
  }

  /* ---------- COMMENT ---------- */
  async getComment(id) {
    const n = assertPositiveInt(id, "id");
    const c = this.comments.find((x) => x.id === n && !x.hidden);
    return publicRow(c ? { ...c } : null);
  }
  async getCommentInternal(id) {
    const n = assertPositiveInt(id, "id");
    const c = this.comments.find((x) => x.id === n);
    return c ? { ...c } : null;
  }
  async listComments({ idProject = null, key_table = null, page = 1, limit = 20, sort = "id", order = "DESC", includeHidden = false } = {}) {
    const p = assertPositiveInt(page, "page");
    const l = Math.min(100, assertPositiveInt(limit, "limit"));
    const col = assertSafeIdent(sort, "sort");
    if (!ALLOWED_COMMENT_SORT.has(col)) throw new Error(`sort chỉ cho phép: ${[...ALLOWED_COMMENT_SORT].join(", ")}`);
    const dir = String(order).toUpperCase();
    if (!ALLOWED_ORDER.has(dir)) throw new Error("order chỉ cho phép ASC / DESC");

    let list = this.comments.map((x) => ({ ...x }));
    if (!includeHidden) list = list.filter((x) => !x.hidden);
    if (idProject) { const ip = assertPositiveInt(idProject, "idProject"); list = list.filter((x) => x.idProject === ip); }
    if (key_table) { const k = assertKeyTable(key_table); list = list.filter((x) => x.key_table === k); }
    list.sort((a, b) => {
      const A = a[col], B = b[col];
      if (A == null) return 1;
      if (B == null) return -1;
      if (A instanceof Date && B instanceof Date) return dir === "ASC" ? A - B : B - A;
      if (typeof A === "number" && typeof B === "number") return dir === "ASC" ? A - B : B - A;
      return dir === "ASC" ? String(A).localeCompare(String(B)) : String(B).localeCompare(String(A));
    });
    const total = list.length;
    const offset = (p - 1) * l;
    return {
      items: list.slice(offset, offset + l).map(publicRow),
      page: p, limit: l, total, totalPages: Math.ceil(total / l),
    };
  }
  async createComment({ key_table, idProject, context }) {
    const k  = assertKeyTable(key_table);
    const ip = assertPositiveInt(idProject, "idProject");
    const ct = assertSafeString(context, "context", { min: 1, max: 100 });
    const now = this._now();
    const row = {
      id: this.seq.comment++, key_table: k, idProject: ip,
      context: ct, hidden: 0, created_at: now, update_at: now,
    };
    this.comments.push(row);
    return { ...row };
  }
  async updateComment(id, { context }) {
    const n = assertPositiveInt(id, "id");
    const c = this.comments.find((x) => x.id === n);
    if (!c) throw new Error("Không tìm thấy comment");
    c.context = assertSafeString(context, "context", { min: 1, max: 100 });
    c.update_at = this._now();
    return { ...c };
  }
  async deleteComment(id) {
    const n = assertPositiveInt(id, "id");
    const i = this.comments.findIndex((x) => x.id === n);
    if (i === -1) return false;
    this.comments.splice(i, 1);
    return true;
  }
  async hideComment(id, hidden = 1) {
    const n = assertPositiveInt(id, "id");
    const c = this.comments.find((x) => x.id === n);
    if (!c) return false;
    c.hidden = hidden ? 1 : 0;
    c.update_at = this._now();
    return true;
  }

  /* ---------- OTP ---------- */
  async requestOTP(userId, password, ttlMs = 5 * 60 * 1000) {
    const n = assertPositiveInt(userId, "userId");
    const ok = await this.verifyPassword(n, password);
    if (!ok) throw new Error("Mật khẩu không đúng");

    const user = this.users.find((x) => x.id === n);
    if (!user) throw new Error("Không tìm thấy user");
    const k = user.key_table;

    // Deactivate cũ
    this.otps.filter((x) => x.key_table === k).forEach((x) => { x.active = 0; });

    const otp = genOtp2Digit();
    const tempToken = genTempToken();
    const row = {
      id: this.seq.otp++, active: 1, OTP: otp, token: tempToken,
      key_table: k, CreatDateTimes: this._now(),
    };
    this.otps.push(row);
    return { id: row.id, otp, token: tempToken, expiresIn: Math.floor(ttlMs / 1000) };
  }
  async verifyOTPByToken(tempToken, otp) {
    const t = assertSafeString(tempToken, "token", { min: 1, max: 256 });
    const o = assertSafeString(otp, "otp", { min: 1, max: 2 });
    const found = [...this.otps].reverse().find((x) => x.token === t && x.OTP === o && x.active === 1);
    if (!found) return { ok: false, message: "OTP hoặc token không hợp lệ / đã dùng" };
    found.active = 0;
    return { ok: true, id: found.id };
  }
  async getOTP(id) {
    const n = assertPositiveInt(id, "id");
    const o = this.otps.find((x) => x.id === n);
    return publicRow(o ? { ...o } : null);
  }
  async getOTPInternal(id) {
    const n = assertPositiveInt(id, "id");
    const o = this.otps.find((x) => x.id === n);
    return o ? { ...o } : null;
  }
  async listOTPByKey(key_table) {
    const k = assertKeyTable(key_table);
    return this.otps.filter((x) => x.key_table === k).map((x) => publicRow({ ...x }));
  }
  async deleteOTP(id) {
    const n = assertPositiveInt(id, "id");
    const i = this.otps.findIndex((x) => x.id === n);
    if (i === -1) return false;
    this.otps.splice(i, 1);
    return true;
  }

  /* ---------- SEED ---------- */
  async seedSampleData(list = SAMPLE_USERS) {
    let inserted = 0;
    for (const u of list) {
      if (this.users.some((x) => x.username === u.username)) continue;
      const pubU = await this.createUser({ ...u, token: "None" });
      const fullU = this.users.find((x) => x.id === pubU.id);
      await this.upsertProfile(fullU.key_table, {
        name: u.username, LastName: "Demo", Avatar: "None", Location: "Vietnam", phone: "0000000000",
      });
      await this.createProject({
        key_table: fullU.key_table,
        name: `Project của ${u.username}`,
        image: "None",
        description: "Project mẫu seed (in-memory)",
        technologies: JSON.stringify(["Node.js", "MariaDB"]),
        status: "Completed",
      });
      inserted++;
      console.log(`  + seeded: ${u.username}`);
    }
    console.log(`🌱 Seed xong (in-memory). Thêm mới ${inserted} user.`);
    return { inserted };
  }
  async close() {}
}

module.exports = {
  MemoryHandler, SAMPLE_USERS,
  sha256, genKeyTable, genTempToken, genOtp2Digit,
  publicUser, publicRow,
};