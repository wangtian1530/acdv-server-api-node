// routing.js
"use strict";

/**
 * HanderRouting - Router cho HTTP server thuần Node.js
 * Hỗ trợ:
 *  - Đăng ký route: add / get / post / put / delete / patch / register
 *  - Path params: /api/users/:id
 *  - Handler async (trả Promise)
 *  - Prefix khi khởi tạo: new HanderRouting("/api/users")
 *  - group(path, callback): nhóm route con
 *  - use(subRouter): gắn router con vào router cha
 *  - Trả về { status, data } giống format trong server.js
 */
class HanderRouting {
  /**
   * @param {string} [prefix=""] - Tiền tố chung cho mọi route
   */
  constructor(prefix = "") {
    this.prefix = this._normalizePrefix(prefix);
    // Mỗi route: { method, path, handler, pattern: { regex, keys } }
    this.routes = [];
  }

  // ====== Chuẩn hoá prefix ======
  _normalizePrefix(prefix) {
    if (!prefix || prefix === "/") return "";
    let p = String(prefix).trim();
    if (!p.startsWith("/")) p = "/" + p;
    // bỏ dấu / ở cuối (trừ khi chính là "/")
    p = p.replace(/\/+$/, "");
    return p;
  }

  // ====== Đăng ký route ======
  add(method, path, handler) {
    if (typeof handler !== "function") {
      throw new TypeError("handler phải là function");
    }
    const fullPath = this._joinPath(this.prefix, path);
    this.routes.push({
      method: String(method).toUpperCase(),
      path: fullPath,
      handler,
      pattern: this._buildPattern(fullPath),
    });
    return this;
  }

  get(path, handler)    { return this.add("GET", path, handler); }
  post(path, handler)   { return this.add("POST", path, handler); }
  put(path, handler)    { return this.add("PUT", path, handler); }
  delete(path, handler) { return this.add("DELETE", path, handler); }
  patch(path, handler)  { return this.add("PATCH", path, handler); }

  /**
   * Đăng ký hàng loạt từ mảng:
   * [{ method, path, handler }, ...]
   */
  register(routes) {
    if (!Array.isArray(routes)) return this;
    for (const r of routes) {
      if (!r || !r.method || !r.path || typeof r.handler !== "function") continue;
      this.add(r.method, r.path, r.handler);
    }
    return this;
  }

  /**
   * Nhóm route con: group("/api/xxxx", (r) => { r.get("/hello", ...) })
   * - `r` là router con có prefix = prefix cha + path nhóm
   */
  group(path, callback) {
    if (typeof callback !== "function") return this;
    const groupPath = this._joinPath(this.prefix, path);
    const subRouter = new HanderRouting(groupPath);
    callback(subRouter);
    this.routes.push(...subRouter.routes);
    return this;
  }

  /**
   * Gắn router con vào router cha (giữ nguyên prefix của router con).
   * Dùng cho: router.use(usersRouter)
   */
  use(subRouter) {
    if (!subRouter || !Array.isArray(subRouter.routes)) {
      throw new TypeError("use() cần một HanderRouting instance");
    }
    // Copy routes nguyên trạng (đã có full path + pattern riêng)
    for (const r of subRouter.routes) {
      this.routes.push(r);
    }
    return this;
  }

  // ====== Nối path an toàn ======
  _joinPath(base, sub) {
    const b = this._normalizePrefix(base);
    let s = String(sub || "").trim();
    if (s === "" || s === "/") return b || "/";
    if (!s.startsWith("/")) s = "/" + s;
    return (b + s) || "/";
  }

  // ====== Chuyển path -> regex (hỗ trợ :param) ======
  _buildPattern(path) {
    const keys = [];
    const normalized = path.length > 1 ? path.replace(/\/+$/, "") : path;

    const regexStr = normalized
      .replace(/[.*+?^${}()|[\]\\]/g, "\\$&") // escape ký tự đặc biệt
      .replace(/:([A-Za-z0-9_]+)/g, (_, key) => {
        keys.push(key);
        return "([^/]+)";
      });

    return {
      regex: new RegExp(`^${regexStr}/?$`),
      keys,
    };
  }

  // ====== Tìm route khớp ======
  match(method, path) {
    const upper = String(method || "").toUpperCase();
    const cleanPath = path && path.length > 1 ? path.replace(/\/+$/, "") : path;

    for (const route of this.routes) {
      if (route.method !== upper) continue;
      const m = route.pattern.regex.exec(cleanPath);
      if (!m) continue;

      const params = {};
      route.pattern.keys.forEach((key, i) => {
        try {
          params[key] = decodeURIComponent(m[i + 1]);
        } catch {
          params[key] = m[i + 1];
        }
      });

      return { route, params };
    }
    return null;
  }

  // ====== Xử lý request ======
  // ctx: { url, path, query, body, headers, method }
  // -> { status, data }
  async handle(ctx = {}) {
    const { method, path } = ctx;

    const found = this.match(method, path);
    if (!found) {
      return {
        status: 404,
        data: {
          status: "error",
          message: "Đường dẫn API không tồn tại (404)",
          path,
          method,
        },
      };
    }

    try {
      const result = await found.route.handler({
        ...ctx,
        params: found.params,
      });

      if (!result || typeof result !== "object") {
        return { status: 200, data: {} };
      }
      return {
        status: result.status || 200,
        data: result.data !== undefined ? result.data : result,
      };
    } catch (err) {
      return {
        status: 500,
        data: {
          status: "error",
          message: "Lỗi server",
          detail: err.message,
        },
      };
    }
  }
}

module.exports = HanderRouting;