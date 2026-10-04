// routes/index.js
"use strict";

const crypto = require("crypto");
const HandlerRouting = require("../system/routing");
const Method = require("../system/method");
const config = require("../config");

/* ============================================================
 *  AUTH GUARD
 * ============================================================ */
class AuthGuard {
  constructor(requireAuth) {
    if (typeof requireAuth !== "function") throw new TypeError("AuthGuard cần hàm requireAuth(ctx)");
    this._requireAuth = requireAuth;
  }
  secured(fn) {
    return async (ctx) => {
      const blocked = await this._requireAuth(ctx);
      if (blocked) return blocked;
      return await fn(ctx);
    };
  }
  check(ctx) { return this._requireAuth(ctx); }
}

/* ============================================================
 *  HANDLERS
 * ============================================================ */
function makeHandlers({ db, security, secured, handleWith }) {

  const ok  = (data, status = 200) => ({ status, data: { status: "success", ...data } });
  const err = (message, status = 400, extra = {}) => ({ status, data: { status: "error", message, ...extra } });
  const pendingRegistrations = new Map();
  const registrationTtlMs = config.security.otpTtlMs || 5 * 60 * 1000;

  function deletePendingRegistration(token) {
    const registration = pendingRegistrations.get(token);
    if (registration?.expiresTimer) clearTimeout(registration.expiresTimer);
    pendingRegistrations.delete(token);
  }

  function removeExpiredRegistrations() {
    const now = Date.now();
    for (const [token, registration] of pendingRegistrations) {
      if (registration.expiresAt <= now) deletePendingRegistration(token);
    }
  }

  async function verifyPendingRegistration({ body }) {
    const { email, token, otp } = body || {};
    if (!email || !token || !otp) return err("Thiếu email, token hoặc otp", 400);

    removeExpiredRegistrations();
    const registration = pendingRegistrations.get(String(token));
    if (!registration) return err("Đăng ký không tồn tại hoặc OTP đã hết hạn", 400);
    if (registration.email !== String(email).trim().toLowerCase()) {
      return err("Email không khớp với mã OTP", 400);
    }
    if (registration.otp !== String(otp).trim()) {
      registration.attempts += 1;
      if (registration.attempts >= 5) deletePendingRegistration(String(token));
      return err("OTP không hợp lệ", 400);
    }
    if (registration.verifying) return err("Yêu cầu xác minh đang được xử lý", 409);

    registration.verifying = true;
    try {
      const user = await db.createUser({
        username: registration.username,
        password: registration.password,
        email: registration.email,
        avatar: "None",
        token: "None",
        active: "1",
      });
      deletePendingRegistration(String(token));
      return ok({
        message: "Đăng ký thành công — email đã được xác minh",
        data: user,
      }, 201);
    } catch (e) {
      registration.verifying = false;
      return err(e.message, 400);
    }
  }

  /* ---------------------------------------------------------
   *  🔒 Lấy key_table từ session
   * --------------------------------------------------------- */
  async function resolveKeyTable(ctx) {
    const s = ctx.session;
    if (!s || !s.authenticated || !s.userId) {
      const e = new Error("Yêu cầu đăng nhập");
      e.httpStatus = 401;
      throw e;
    }
    const u = await db.getUserInternal(s.userId);
    if (!u) {
      const e = new Error("Session không hợp lệ");
      e.httpStatus = 401;
      throw e;
    }
    return u.key_table;
  }

  /* ---------------------------------------------------------
   *  👑 isAdmin — dựa vào username trong session.meta
   * --------------------------------------------------------- */
  function isAdmin(ctx) {
    const meta = ctx.session?.meta || {};
    const admins = config.security.adminUsernames || [];
    return !!ctx.session?.authenticated && admins.includes(meta.username);
  }

  return {
    /* ---------- PUBLIC ---------- */
    home: (ctx) => ok({
      message: "Node.js HTTP Server API thuần 🚀 (ACDV Teams)",
      timestamp: new Date().toISOString(),
      session: ctx.session ? ctx.session.toJSON() : null,
      rateLimit: ctx.rateLimit || null,
      policy: {
        token: "PUBLIC — nhận và trả",
        key_table: "PRIVATE — server-only (không nhận, không xuất)",
        user_delete: "❌ Cấm — user không được xóa chính mình hoặc người khác",
        admin: "Chỉ ẨN (hide) — không có quyền XÓA",
        otp: "Request cần password → sinh temp token riêng",
        project: "Chỉ chủ sở hữu được SỬA/XÓA. Admin chỉ ẩn.",
        comment: "Author sửa/xóa. Chủ project chỉ getUserẩn.",
      },
      endpoints: {
        AUTH: [
          "POST /auth/login   (body: { username|email, password })",
          "POST /auth/logout  (header X-Session-Token)",
          "POST /auth/register/request (username, password, email → RAM 5 phút; OTP ghi log)",
          "POST /auth/register/verify  (email, token, otp → tạo user trong DB sau xác minh)",
          "GET  /auth/me      🔒",
        ],
        USER: [
          "GET /users/me  🔒",
          "PUT /users/me  🔒 (body: { username?, password?, avatar?, email?, token?, active? })",
          "POST /users    (đăng ký, public — key_table server tự sinh)",
          "❌ DELETE /users/me  → 403 (tạm khóa)",
          "❌ Xem user khác → KHÔNG CÓ ROUTE",
        ],
        PROFILE: [
          "GET /profiles/me  🔒",
          "PUT /profiles/me  🔒 (upsert — luôn UPDATE, không xóa)",
        ],
        PROJECT: [
          "GET    /projects?page=&limit=&q=&status=",
          "GET    /projects/me    🔒 (kể cả hidden)",
          "GET    /projects/:id",
          "POST   /projects       🔒",
          "PUT    /projects/:id   🔒 (owner only)",
          "DELETE /projects/:id   🔒 (owner only, HARD)",
          "POST   /projects/:id/hide     🔒 (admin only — SOFT)",
          "POST   /projects/:id/unhide   🔒 (admin only)",
        ],
        COMMENT: [
          "GET    /projects/:id/comments",
          "POST   /projects/:id/comments  🔒",
          "PUT    /comments/:id           🔒 (author only)",
          "DELETE /comments/:id           🔒 (author only, HARD)",
          "POST   /comments/:id/hide      🔒 (project owner hoặc admin)",
          "POST   /comments/:id/unhide    🔒 (project owner hoặc admin)",
        ],
        OTP: [
          "POST /otp/request  🔒 (body: { password })  ← cần password",
          "POST /otp/verify   (body: { token, otp })   ← dùng temp token, không cần login",
          "GET  /otp/me       🔒",
          "DELETE /otp/:id    🔒 (owner only)",
        ],
        MISC: [
          "GET /", "GET /health",
          "GET /xxxx/hello", "GET /xxxx/echo/:msg",
          "GET /admin 🔒 (admin only)",
        ],
      },
    }),

    health: () => ok({ status2: "ok", uptime: process.uptime(), security: security.stats() }),
    hello: () => ok({ msg: "hello xxxx 👋" }),
    echo: ({ params }) => ok({ youSaid: params.msg }),

    /* ---------- USER ---------- */
    createUser: verifyPendingRegistration,

    requestRegisterOTP: async ({ body }) => {
      try {
        const { username: rawUsername, password, email: rawEmail } = body || {};
        if (typeof rawUsername !== "string" || typeof password !== "string" || typeof rawEmail !== "string") {
          return err("Username, password và email phải là chuỗi", 400);
        }
        const username = String(rawUsername || "").trim();
        const email = String(rawEmail || "").trim().toLowerCase();
        if (!username || !password.trim() || !email) {
          return err("Thiếu username, password hoặc email", 400);
        }
        if (username.length > 50 || password.length > 255 || email.length > 50 || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
          return err("Username, password hoặc email không hợp lệ", 400);
        }

        removeExpiredRegistrations();
        const existingUser = await db.getUserByUsername(username);
        if (existingUser) return err("Username đã tồn tại", 409);

        const existingEmail = await db.getUserByEmail(email);
        if (existingEmail) return err("Email đã tồn tại", 409);

        for (const [pendingToken, registration] of pendingRegistrations) {
          if (registration.username === username || registration.email === email) {
            deletePendingRegistration(pendingToken);
          } else if (registration.username === email || registration.email === username) {
            return err("Username hoặc email đang được đăng ký", 409);
          }
        }

        const otp = String(crypto.randomInt(0, 1000000)).padStart(6, "0");
        const token = `register_${crypto.randomBytes(32).toString("hex")}`;
        const expiresAt = Date.now() + registrationTtlMs;
        const registration = {
          username,
          password,
          email,
          otp,
          expiresAt,
          attempts: 0,
          verifying: false,
        };
        registration.expiresTimer = setTimeout(() => deletePendingRegistration(token), registrationTtlMs);
        if (registration.expiresTimer.unref) registration.expiresTimer.unref();
        pendingRegistrations.set(token, registration);

        // Development mode: khi chưa tích hợp email, OTP chỉ được in ở console server.
        console.log(`[REGISTER OTP] email=${email} otp=${otp} expires_in=${Math.floor(registrationTtlMs / 1000)}s`);
        return ok({
          message: "Yêu cầu đăng ký đã được tạo. Nhập OTP để xác minh; mã có hiệu lực 5 phút.",
          data: {
            email,
            token,
            expires_in: Math.floor(registrationTtlMs / 1000),
          },
        }, 201);
      } catch (e) { return err(e.message, 400); }
    },

    verifyRegisterOTP: verifyPendingRegistration,

    getMyUser: async (ctx) => {
      try {
        const u = await db.getUser(ctx.session.userId);
        if (!u) return err("Không tìm thấy user", 404);
        return ok({ data: u });
      } catch (e) { return err(e.message, 400); }
    },

    updateMyUser: async (ctx) => {
      try {
        const { key_table: _k, ...patch } = ctx.body || {};
        const u = await db.updateUser(ctx.session.userId, patch);
        return ok({ message: "Cập nhật thành công", data: u });
      } catch (e) { return err(e.message, 400); }
    },

    /** ❌ Cấm xóa chính mình — luôn 403 */
    deleteMyUser: () => err("Tính năng xóa tài khoản đang tạm khóa", 403),

    /* ---------- PROFILE: chỉ /me, không có DELETE ---------- */
    getMyProfile: async (ctx) => {
      try {
        const k = await resolveKeyTable(ctx);
        const p = await db.getProfile(k);
        if (!p) return err("Chưa có profile", 404);
        return ok({ data: p });
      } catch (e) { return err(e.message, e.httpStatus || 400); }
    },

    upsertMyProfile: async (ctx) => {
      try {
        const k = await resolveKeyTable(ctx);
        const p = await db.upsertProfile(k, ctx.body || {});
        return ok({ message: "Lưu profile thành công", data: p });
      } catch (e) { return err(e.message, e.httpStatus || 400); }
    },

    /* ---------- PROJECT ---------- */
    listProjects: async (ctx) => {
      try {
        const includeHidden = isAdmin(ctx) && String(ctx.query.include_hidden || "") === "1";
        const r = await db.listProjects({
          page:   ctx.query.page  || 1,
          limit:  ctx.query.limit || 20,
          sort:   ctx.query.sort  || "id",
          order:  ctx.query.order || "DESC",
          q:      ctx.query.q     || null,
          status: ctx.query.status || null,
          key_table: null,
          includeHidden,
        });
        return ok({ total: r.total, page: r.page, limit: r.limit, totalPages: r.totalPages, data: r.items });
      } catch (e) { return err(e.message, 400); }
    },

    listMyProjects: async (ctx) => {
      try {
        const k = await resolveKeyTable(ctx);
        const r = await db.listProjects({
          page:  ctx.query.page  || 1,
          limit: ctx.query.limit || 20,
          sort:  ctx.query.sort  || "id",
          order: ctx.query.order || "DESC",
          q:     ctx.query.q     || null,
          status: ctx.query.status || null,
          key_table: k,
          includeHidden: true,   // chủ sở hữu thấy cả hidden
        });
        return ok({ total: r.total, page: r.page, limit: r.limit, totalPages: r.totalPages, data: r.items });
      } catch (e) { return err(e.message, e.httpStatus || 400); }
    },

    getProject: async (ctx) => {
      try {
        const p = await db.getProjectInternal(ctx.params.id);
        if (!p) return err(`Không tìm thấy project id=${ctx.params.id}`, 404);
        if (p.hidden === 1) {
          // Chỉ owner hoặc admin xem được
          const admin = isAdmin(ctx);
          let owner = false;
          if (ctx.session?.authenticated) {
            const k = await resolveKeyTable(ctx).catch(() => null);
            owner = k === p.key_table;
          }
          if (!admin && !owner) return err(`Không tìm thấy project id=${ctx.params.id}`, 404);
        }
        const { key_table, ...safe } = p;
        return ok({ data: safe });
      } catch (e) { return err(e.message, 400); }
    },

    createProject: async (ctx) => {
      try {
        const k = await resolveKeyTable(ctx);
        const { key_table: _drop, ...b } = ctx.body || {};
        const p = await db.createProject({
          key_table: k,
          name:         b.name,
          image:        b.image,
          description:  b.description,
          technologies: b.technologies,
          status:       b.status,
        });
        return ok({ message: "Tạo project thành công", data: p }, 201);
      } catch (e) { return err(e.message, e.httpStatus || 400); }
    },

    updateProject: async (ctx) => {
      try {
        const k = await resolveKeyTable(ctx);
        const project = await db.getProjectInternal(ctx.params.id);
        if (!project) return err("Không tìm thấy project", 404);
        if (project.key_table !== k) return err("Bạn không phải chủ project này", 403);

        const { key_table: _drop, ...patch } = ctx.body || {};
        const p = await db.updateProject(ctx.params.id, patch);
        const { key_table, ...safe } = p;
        return ok({ message: "Cập nhật project thành công", data: safe });
      } catch (e) { return err(e.message, e.httpStatus || 400); }
    },

    deleteProject: async (ctx) => {
      try {
        const k = await resolveKeyTable(ctx);
        const project = await db.getProjectInternal(ctx.params.id);
        if (!project) return err("Không tìm thấy project", 404);
        if (project.key_table !== k) return err("Bạn không phải chủ project này", 403);

        await db.deleteProject(ctx.params.id);
        return ok({ message: "Đã xóa project (hard delete)" });
      } catch (e) { return err(e.message, e.httpStatus || 400); }
    },

    /** Admin only — soft hide */
    hideProject: async (ctx) => {
      try {
        if (!isAdmin(ctx)) return err("Chỉ admin mới có quyền ẩn project", 403);
        const exists = await db.getProjectInternal(ctx.params.id);
        if (!exists) return err("Không tìm thấy project", 404);
        await db.hideProject(ctx.params.id, 1);
        return ok({ message: "Đã ẩn project" });
      } catch (e) { return err(e.message, e.httpStatus || 400); }
    },

    unhideProject: async (ctx) => {
      try {
        if (!isAdmin(ctx)) return err("Chỉ admin mới có quyền bỏ ẩn", 403);
        const exists = await db.getProjectInternal(ctx.params.id);
        if (!exists) return err("Không tìm thấy project", 404);
        await db.hideProject(ctx.params.id, 0);
        return ok({ message: "Đã bỏ ẩn project" });
      } catch (e) { return err(e.message, e.httpStatus || 400); }
    },

    /* ---------- COMMENT ---------- */
    listComments: async ({ params, query }) => {
      try {
        const r = await db.listComments({
          idProject: params.id,
          key_table: null,
          page:  query.page  || 1,
          limit: query.limit || 20,
          sort:  query.sort  || "id",
          order: query.order || "DESC",
          includeHidden: false,
        });
        return ok({ total: r.total, page: r.page, limit: r.limit, totalPages: r.totalPages, data: r.items });
      } catch (e) { return err(e.message, 400); }
    },

    createComment: async (ctx) => {
      try {
        const k = await resolveKeyTable(ctx);
        const { key_table: _drop, context } = ctx.body || {};
        const c = await db.createComment({
          key_table: k,
          idProject: ctx.params.id,
          context,
        });
        const { key_table, ...safe } = c;
        return ok({ message: "Đã thêm bình luận", data: safe }, 201);
      } catch (e) { return err(e.message, e.httpStatus || 400); }
    },

    updateComment: async (ctx) => {
      try {
        const k = await resolveKeyTable(ctx);
        const c = await db.getCommentInternal(ctx.params.id);
        if (!c) return err("Không tìm thấy comment", 404);
        if (c.key_table !== k) return err("Bạn không phải tác giả comment", 403);

        const updated = await db.updateComment(ctx.params.id, { context: ctx.body?.context });
        const { key_table, ...safe } = updated;
        return ok({ message: "Đã cập nhật bình luận", data: safe });
      } catch (e) { return err(e.message, e.httpStatus || 400); }
    },

    deleteComment: async (ctx) => {
      try {
        const k = await resolveKeyTable(ctx);
        const c = await db.getCommentInternal(ctx.params.id);
        if (!c) return err("Không tìm thấy comment", 404);
        if (c.key_table !== k) return err("Bạn không phải tác giả comment", 403);

        await db.deleteComment(ctx.params.id);
        return ok({ message: "Đã xóa bình luận (hard delete)" });
      } catch (e) { return err(e.message, e.httpStatus || 400); }
    },

    /** Chủ project hoặc admin — soft hide */
    hideComment: async (ctx) => {
      try {
        const c = await db.getCommentInternal(ctx.params.id);
        if (!c) return err("Không tìm thấy comment", 404);

        const admin = isAdmin(ctx);
        let owner = false;
        if (ctx.session?.authenticated) {
          const k = await resolveKeyTable(ctx).catch(() => null);
          const proj = await db.getProjectInternal(c.idProject);
          owner = proj && proj.key_table === k;
        }
        if (!admin && !owner) return err("Chỉ chủ project hoặc admin mới được ẩn bình luận", 403);

        await db.hideComment(ctx.params.id, 1);
        return ok({ message: "Đã ẩn bình luận" });
      } catch (e) { return err(e.message, e.httpStatus || 400); }
    },

    unhideComment: async (ctx) => {
      try {
        const c = await db.getCommentInternal(ctx.params.id);
        if (!c) return err("Không tìm thấy comment", 404);

        const admin = isAdmin(ctx);
        let owner = false;
        if (ctx.session?.authenticated) {
          const k = await resolveKeyTable(ctx).catch(() => null);
          const proj = await db.getProjectInternal(c.idProject);
          owner = proj && proj.key_table === k;
        }
        if (!admin && !owner) return err("Chỉ chủ project hoặc admin mới được bỏ ẩn", 403);

        await db.hideComment(ctx.params.id, 0);
        return ok({ message: "Đã bỏ ẩn bình luận" });
      } catch (e) { return err(e.message, e.httpStatus || 400); }
    },

    /* ---------- OTP ---------- */
    listMyOTP: async (ctx) => {
      try {
        const k = await resolveKeyTable(ctx);
        const rows = await db.listOTPByKey(k);
        return ok({ data: rows });
      } catch (e) { return err(e.message, e.httpStatus || 400); }
    },

    /** Request OTP — cần password */
    requestOTP: async (ctx) => {
      try {
        const password = ctx.body?.password;
        if (!password) return err("Thiếu password", 400);
        const r = await db.requestOTP(ctx.session.userId, password, config.security.otpTtlMs);
        return ok({
          message: "Đã sinh OTP và token tạm",
          data: {
            otp_id: r.id,
            otp:    r.otp,        // ⚠️ Demo trả luôn; thực tế gửi qua email/SMS
            token:  r.token,      // 🔑 Temp token (KHÁC session token)
            expires_in: r.expiresIn,
          },
        }, 201);
      } catch (e) { return err(e.message, e.httpStatus || 400); }
    },

    /** Verify OTP bằng temp token — không cần login */
    verifyOTP: async (ctx) => {
      try {
        const { token, otp } = ctx.body || {};
        if (!token || !otp) return err("Thiếu token hoặc otp", 400);
        const r = await db.verifyOTPByToken(token, otp);
        if (!r.ok) return err(r.message, 400);
        return ok({ message: "Xác thực OTP thành công", id: r.id });
      } catch (e) { return err(e.message, e.httpStatus || 400); }
    },

    deleteOTP: async (ctx) => {
      try {
        const k = await resolveKeyTable(ctx);
        const o = await db.getOTPInternal(ctx.params.id);
        if (!o) return err("Không tìm thấy OTP", 404);
        if (o.key_table !== k) return err("Bạn không phải chủ OTP này", 403);

        await db.deleteOTP(ctx.params.id);
        return ok({ message: "Đã xóa OTP" });
      } catch (e) { return err(e.message, e.httpStatus || 400); }
    },

    /* ---------- AUTH ---------- */
    login: async ({ req, body }) => {
      const identifier = body?.username || body?.email;
      const password   = body?.password;
      if (!identifier || !password) return err("Thiếu username/email hoặc password", 400);

      try {
        const user = await db.verifyLogin(identifier, password);
        if (!user) return err("Sai thông tin đăng nhập", 401);

        const session = security.login(req, user.id, {
          meta: { username: user.username, email: user.email },
        });

        return ok({
          message: "Đăng nhập thành công",
          token: session.token,
          user,
          session: session.toJSON(),
        });
      } catch (e) { return err(e.message, 400); }
    },

    logout: ({ token }) => {
      const okLogout = security.logout(token, "user_logout");
      return {
        status: okLogout ? 200 : 400,
        data: {
          status: okLogout ? "success" : "error",
          message: okLogout ? "Đã đăng xuất" : "Không tìm thấy session",
        },
      };
    },

    me: (ctx) => ok({ session: ctx.session.toJSON() }),

    admin: (ctx) => {
      if (!isAdmin(ctx)) return err("Chỉ admin truy cập được", 403);
      return ok({
        msg: "Khu vực admin ✅",
        note: "Admin chỉ có quyền ẨN — không có quyền XÓA.",
        session: ctx.session.toJSON(),
      });
    },

    data: ({ body }) => ok({ message: "Đã nhận dữ liệu thành công!", receivedData: body }, 201),
  };
}

/* ============================================================
 *  BUILD ROUTER
 * ============================================================ */
function buildRouter({ security, db, requireAuth }) {
  const router = new HandlerRouting();
  const guard  = new AuthGuard(requireAuth);
  const secured = guard.secured.bind(guard);

  const handleWith = (m) => ({ url, query, body, headers, params }) => {
    const inst = new Method({ params: { medthod: m, url, query, body, headers, params } });
    const result = inst.handle();
    return { status: result.ok ? 200 : result.status || 400, data: result };
  };

  const h = makeHandlers({ db, security, secured, handleWith });

  const routers = {
    rou: "",
    data: {
      GET: [
        { path: "",                   handler: h.home },
        { path: "health",             handler: h.health },

        // USER — chỉ /me (không có list, không có :id)
        { path: "users/me",           handler: secured(h.getMyUser) },

        // PROFILE — chỉ /me
        { path: "profiles/me",        handler: secured(h.getMyProfile) },

        // PROJECT
        { path: "projects/me",             handler: secured(h.listMyProjects) },
        { path: "projects/:id/comments",   handler: h.listComments },
        { path: "projects/:id",            handler: h.getProject },
        { path: "projects",                handler: h.listProjects },

        // OTP
        { path: "otp/me",             handler: secured(h.listMyOTP) },

        // PROTECTED
        { path: "auth/me",            handler: secured(h.me) },
        { path: "admin",              handler: secured(h.admin) },

        // MISC
        { path: "xxxx/hello",         handler: h.hello },
        { path: "xxxx/echo/:msg",     handler: h.echo },
        { path: "handle",             handler: handleWith("GET") },
      ],
      POST: [
        // AUTH
        { path: "auth/login",              handler: h.login },
        { path: "auth/logout",             handler: h.logout },
        { path: "auth/register/request",   handler: h.requestRegisterOTP },
        { path: "auth/register/verify",    handler: h.verifyRegisterOTP },

        // USER đăng ký
        { path: "users",                   handler: h.createUser },

        // PROJECT
        { path: "projects",                handler: secured(h.createProject) },
        { path: "projects/:id/hide",       handler: secured(h.hideProject) },
        { path: "projects/:id/unhide",     handler: secured(h.unhideProject) },
        { path: "projects/:id/comments",   handler: secured(h.createComment) },

        // COMMENT hide/unhide
        { path: "comments/:id/hide",       handler: secured(h.hideComment) },
        { path: "comments/:id/unhide",     handler: secured(h.unhideComment) },

        // OTP
        { path: "otp/request",             handler: secured(h.requestOTP) },
        { path: "otp/verify",              handler: h.verifyOTP },   // ← public, dùng temp token

        // MISC
        { path: "data",                    handler: h.data },
        { path: "handle",                  handler: handleWith("POST") },
      ],
      PUT: [
        { path: "users/me",           handler: secured(h.updateMyUser) },
        { path: "profiles/me",        handler: secured(h.upsertMyProfile) },
        { path: "projects/:id",       handler: secured(h.updateProject) },
        { path: "comments/:id",       handler: secured(h.updateComment) },
        { path: "handle",             handler: handleWith("PUT") },
      ],
      DELETE: [
        { path: "users/me",           handler: secured(h.deleteMyUser) },   // ← luôn 403
        { path: "projects/:id",       handler: secured(h.deleteProject) },
        { path: "comments/:id",       handler: secured(h.deleteComment) },
        { path: "otp/:id",            handler: secured(h.deleteOTP) },
        { path: "handle",             handler: handleWith("DELETE") },
      ],
    },
  };

  const joinPath = (base, p) =>
    (base.replace(/\/+$/, "") + "/" + p.replace(/^\/+/, "")).replace(/\/$/, "") || "/";

  for (const [method, list] of Object.entries(routers.data)) {
    const register = router[method.toLowerCase()].bind(router);
    for (const { path, handler } of list) {
      if (typeof handler !== "function") throw new Error(`Route ${method} ${path} thiếu handler`);
      register(joinPath(routers.rou, path), handler);
    }
  }

  router.get("/", h.home);
  return router;
}

module.exports = { buildRouter, AuthGuard };