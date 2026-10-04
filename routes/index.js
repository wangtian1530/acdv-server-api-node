// routes/index.js
"use strict";

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
        comment: "Author sửa/xóa. Chủ project chỉ ẩn.",
      },
      endpoints: {
        AUTH: [
          "POST /api/auth/login   (body: { username|email, password })",
          "POST /api/auth/logout  (header X-Session-Token)",
          "GET  /api/auth/me      🔒",
        ],
        USER: [
          "GET /api/users/me  🔒",
          "PUT /api/users/me  🔒 (body: { username?, password?, avatar?, email?, token?, active? })",
          "POST /api/users    (đăng ký, public — key_table server tự sinh)",
          "❌ DELETE /api/users/me  → 403 (tạm khóa)",
          "❌ Xem user khác → KHÔNG CÓ ROUTE",
        ],
        PROFILE: [
          "GET /api/profiles/me  🔒",
          "PUT /api/profiles/me  🔒 (upsert — luôn UPDATE, không xóa)",
        ],
        PROJECT: [
          "GET    /api/projects?page=&limit=&q=&status=",
          "GET    /api/projects/me    🔒 (kể cả hidden)",
          "GET    /api/projects/:id",
          "POST   /api/projects       🔒",
          "PUT    /api/projects/:id   🔒 (owner only)",
          "DELETE /api/projects/:id   🔒 (owner only, HARD)",
          "POST   /api/projects/:id/hide     🔒 (admin only — SOFT)",
          "POST   /api/projects/:id/unhide   🔒 (admin only)",
        ],
        COMMENT: [
          "GET    /api/projects/:id/comments",
          "POST   /api/projects/:id/comments  🔒",
          "PUT    /api/comments/:id           🔒 (author only)",
          "DELETE /api/comments/:id           🔒 (author only, HARD)",
          "POST   /api/comments/:id/hide      🔒 (project owner hoặc admin)",
          "POST   /api/comments/:id/unhide    🔒 (project owner hoặc admin)",
        ],
        OTP: [
          "POST /api/otp/request  🔒 (body: { password })  ← cần password",
          "POST /api/otp/verify   (body: { token, otp })   ← dùng temp token, không cần login",
          "GET  /api/otp/me       🔒",
          "DELETE /api/otp/:id    🔒 (owner only)",
        ],
        MISC: [
          "GET /", "GET /health",
          "GET /api/xxxx/hello", "GET /api/xxxx/echo/:msg",
          "GET /api/admin 🔒 (admin only)",
        ],
      },
    }),

    health: () => ok({ status2: "ok", uptime: process.uptime(), security: security.stats() }),
    hello: () => ok({ msg: "hello xxxx 👋" }),
    echo: ({ params }) => ok({ youSaid: params.msg }),

    /* ---------- USER ---------- */
    createUser: async ({ body }) => {
      try {
        const { key_table: _drop, ...safe } = body || {};
        const user = await db.createUser(safe);
        return ok({ message: "Đăng ký thành công", data: user }, 201);
      } catch (e) { return err(e.message, 400); }
    },

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
    rou: "/api/",
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