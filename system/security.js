// security.js
"use strict";

const crypto = require("crypto");

/* =========================================================
 * SECURITY MODULE
 *  - TokenBucket      : 1000 req / IP, hồi +2 req mỗi giây
 *  - DeviceFingerprint: ràng buộc Browser + Device
 *  - Session          : anon (random mỗi request) | auth (cố định)
 *  - Security         : quản lý tập trung + middleware cho server.js
 * ========================================================= */

/* ---------------- Logger (log đặc biệt cho TOKEN & SESSION) ---------------- */
const SecurityLog = {
  _out(level, tag, args) {
    const ts = new Date().toISOString();
    const head = `[SECURITY][${level}][${tag}][${ts}]`;
    const fn =
      level === "ERROR" ? console.error :
      level === "WARN"  ? console.warn  :
                          console.log;
    fn(head, ...args);
  },
  info(tag, ...a)  { this._out("INFO", tag, a); },
  warn(tag, ...a)  { this._out("WARN", tag, a); },
  error(tag, ...a) { this._out("ERROR", tag, a); },

  // Log riêng cho TOKEN và SESSION
  token(...a)   { this._out("TOKEN",   "TOKEN",   a); },
  session(...a) { this._out("SESSION", "SESSION", a); },
};

/* ---------------- Token Bucket ---------------- */
class TokenBucket {
  constructor({ capacity = 1000, refillPerSec = 2 } = {}) {
    this.capacity     = capacity;
    this.refillPerSec = refillPerSec;
    this.tokens       = capacity;
    this.last         = Date.now();
  }

  _refill() {
    const now = Date.now();
    const dt  = (now - this.last) / 1000;
    if (dt > 0) {
      this.tokens = Math.min(this.capacity, this.tokens + dt * this.refillPerSec);
      this.last   = now;
    }
  }

  tryConsume(n = 1) {
    this._refill();
    if (this.tokens >= n) {
      this.tokens -= n;
      return true;
    }
    return false;
  }

  get remaining() { this._refill(); return Math.max(0, Math.floor(this.tokens)); }
  get idleMs()    { return Date.now() - this.last; }
}

/* ---------------- Device Fingerprint ---------------- */
class DeviceFingerprint {
  /** Parse User-Agent -> browser / os / device */
  static parseUA(ua = "") {
    const u = String(ua);
    let browser = "Unknown";
    if (/Edg\//i.test(u))                     browser = "Edge";
    else if (/OPR\/|Opera/i.test(u))          browser = "Opera";
    else if (/Firefox\/|FxiOS/i.test(u))      browser = "Firefox";
    else if (/Chrome\/|CriOS/i.test(u))       browser = "Chrome";
    else if (/Safari\//i.test(u))             browser = "Safari";
    else if (/curl|wget|node-fetch|axios|python|bot|crawler|spider/i.test(u))
                                              browser = "Bot/CLI";

    let os = "Unknown";
    if (/Windows NT/i.test(u))                os = "Windows";
    else if (/Android/i.test(u))              os = "Android";
    else if (/iPhone|iPad|iPod/i.test(u))     os = "iOS";
    else if (/Mac OS X/i.test(u))             os = "macOS";
    else if (/Linux/i.test(u))                os = "Linux";

    let device = "Desktop";
    if (/iPad|Tablet/i.test(u))               device = "Tablet";
    else if (/Mobile|Android|iPhone/i.test(u))device = "Mobile";

    return { browser, os, device };
  }

  /** Băm fingerprint để so khớp */
  static hash({ ua = "", lang = "", enc = "", extra = "" } = {}) {
    const raw = `${ua}||${lang}||${enc}||${extra}`;
    return crypto.createHash("sha256").update(raw).digest("hex").slice(0, 32);
  }
}

/* ---------------- Session ---------------- */
class Session {
  constructor(opts = {}) {
    this.token         = opts.token;
    this.userId        = opts.userId ?? null;
    this.authenticated = !!opts.authenticated;

    // Định danh
    this.ip          = opts.ip || "unknown";
    this.userAgent   = opts.userAgent || "";
    this.fingerprint = opts.fingerprint || "";
    this.browser     = opts.browser || "Unknown";
    this.os          = opts.os || "Unknown";
    this.device      = opts.device || "Unknown";

    // Thời gian
    this.createdAt = Date.now();
    this.lastSeen  = Date.now();
    this.ttl       = opts.ttl || 30 * 60 * 1000;
    this.expiresAt = this.createdAt + this.ttl;

    this.meta    = {};
    this.revoked = false;
  }

  touch() {
    this.lastSeen  = Date.now();
    this.expiresAt = this.lastSeen + this.ttl;
  }

  isExpired() {
    return this.revoked || Date.now() > this.expiresAt;
  }

  /** Nâng cấp anon -> auth: token cố định, tăng TTL */
  promote(userId, extra = {}) {
    this.userId        = userId;
    this.authenticated = true;
    this.ttl           = extra.ttl || 60 * 60 * 1000; // 1h
    this.expiresAt     = Date.now() + this.ttl;
    Object.assign(this.meta, extra.meta || {});
    return this;
  }

  /** Kiểm tra ràng buộc IP + Device (chống chiếm phiên) */
  verifyBinding({ ip, fingerprint }) {
    if (!this.authenticated) return { ok: true };
    if (ip && this.ip && ip !== this.ip) {
      return { ok: false, reason: "IP_MISMATCH", expected: this.ip, got: ip };
    }
    if (fingerprint && this.fingerprint && fingerprint !== this.fingerprint) {
      return { ok: false, reason: "DEVICE_MISMATCH" };
    }
    return { ok: true };
  }

  toJSON() {
    return {
      token:         this.token.slice(0, 12) + "...",
      userId:        this.userId,
      authenticated: this.authenticated,
      ip:            this.ip,
      browser:       this.browser,
      os:            this.os,
      device:        this.device,
      createdAt:     this.createdAt,
      lastSeen:      this.lastSeen,
      expiresAt:     this.expiresAt,
    };
  }
}

/* ---------------- Security ---------------- */
class Security {
  constructor(options = {}) {
    this.sessions = new Map();   // token -> Session
    this.ipIndex  = new Map();   // ip    -> Set<token>
    this.ipBucket = new Map();   // ip    -> TokenBucket (rate limit theo IP)

    this.ttl        = options.ttl        ?? 60 * 60 * 1000; // 1h session đã login
    this.anonTtl    = options.anonTtl    ?? 10 * 60 * 1000; // 10' session ẩn danh
    this.capacity   = options.capacity   ?? 1000;           // tối đa 1000 requests
    this.refillPerSec = options.refillPerSec ?? 2;          // +2 req / giây
    this.trustProxy = options.trustProxy !== false;

    this.cookieName = options.cookieName || "sid";
    this.headerName = (options.headerName || "x-session-token").toLowerCase();

    // Dọn dẹp định kỳ
    this._timer = setInterval(() => this.cleanExpired(), 60_000);
    if (this._timer.unref) this._timer.unref();

    SecurityLog.info("BOOT", "Security khởi tạo", {
      capacity: this.capacity,
      refillPerSec: this.refillPerSec,
      ttl: this.ttl,
      anonTtl: this.anonTtl,
    });
  }

  /* ---------- Utils ---------- */
  generateToken(prefix = "sess") {
    return `${prefix}_${crypto.randomBytes(32).toString("hex")}`;
  }

  getClientIp(req) {
    if (this.trustProxy) {
      const xff = req.headers["x-forwarded-for"];
      if (xff) return String(xff).split(",")[0].trim();
      const real = req.headers["x-real-ip"];
      if (real) return String(real).trim();
    }
    return (
      req.socket?.remoteAddress ||
      req.connection?.remoteAddress ||
      "unknown"
    );
  }

  fingerprintOf(req) {
    return DeviceFingerprint.hash({
      ua:   req.headers["user-agent"]       || "",
      lang: req.headers["accept-language"]  || "",
      enc:  req.headers["accept-encoding"]  || "",
    });
  }

  /* ---------- Token từ request ---------- */
  readToken(req) {
    const h = req.headers[this.headerName];
    if (h) return Array.isArray(h) ? h[0] : h;

    const auth = req.headers["authorization"];
    if (auth && /^Bearer\s+/i.test(auth)) return auth.replace(/^Bearer\s+/i, "").trim();

    const cookie = req.headers["cookie"];
    if (cookie) {
      const re = new RegExp(`(?:^|;\\s*)${this.cookieName}=([^;]+)`);
      const m = cookie.match(re);
      if (m) return decodeURIComponent(m[1]);
    }
    return null;
  }

  /* ---------- Session ops ---------- */
  create(req, { authenticated = false, userId = null, ttl } = {}) {
    const ip    = this.getClientIp(req);
    const ua    = req.headers["user-agent"] || "";
    const fp    = this.fingerprintOf(req);
    const parts = DeviceFingerprint.parseUA(ua);

    const token = this.generateToken(authenticated ? "auth" : "anon");
    const session = new Session({
      token,
      userId,
      authenticated,
      ip,
      userAgent:   ua,
      fingerprint: fp,
      browser:     parts.browser,
      os:          parts.os,
      device:      parts.device,
      ttl: ttl ?? (authenticated ? this.ttl : this.anonTtl),
    });

    this._register(session);

    SecurityLog.token(`Cấp token ${authenticated ? "AUTH" : "ANON"}`, {
      token:   token.slice(0, 16) + "...",
      ip,
      browser: parts.browser,
      os:      parts.os,
      device:  parts.device,
    });

    return session;
  }

  get(token) {
    if (!token) return null;
    const s = this.sessions.get(token);
    if (!s) return null;
    if (s.isExpired()) {
      this.destroy(token, "expired");
      SecurityLog.session("Session hết hạn", { token: token.slice(0, 16) + "..." });
      return null;
    }
    return s;
  }

  /** Đăng nhập -> tạo token MỚI (chống session fixation) */
  login(req, userId, extra = {}) {
    // Huỷ token anon cũ nếu có
    const oldToken = this.readToken(req);
    if (oldToken) this.destroy(oldToken, "promote");

    const session = this.create(req, { authenticated: true, userId });
    session.promote(userId, extra);

    SecurityLog.session("LOGIN — đã cấp token cố định", {
      userId,
      token:   session.token.slice(0, 16) + "...",
      ip:      session.ip,
      browser: session.browser,
      os:      session.os,
      device:  session.device,
    });

    return session;
  }

  logout(token, reason = "logout") {
    const s = this.get(token);
    if (!s) return false;
    this.destroy(token, reason);
    SecurityLog.session("LOGOUT — huỷ session", {
      token:  token.slice(0, 16) + "...",
      userId: s.userId,
      reason,
    });
    return true;
  }

  destroy(token, reason = "destroyed") {
    const s = this.sessions.get(token);
    if (!s) return;
    s.revoked = true;
    this.sessions.delete(token);
    const set = this.ipIndex.get(s.ip);
    if (set) {
      set.delete(token);
      if (set.size === 0) this.ipIndex.delete(s.ip);
    }
    SecurityLog.warn("Huỷ session", {
      token: token.slice(0, 16) + "...",
      reason,
      ip: s.ip,
    });
  }

  /* ---------- IP Bucket ---------- */
  _getIpBucket(ip) {
    let b = this.ipBucket.get(ip);
    if (!b) {
      b = new TokenBucket({
        capacity:     this.capacity,
        refillPerSec: this.refillPerSec,
      });
      this.ipBucket.set(ip, b);
    }
    return b;
  }

  /* ---------- Cleanup ---------- */
  cleanExpired() {
    const now = Date.now();
    let n = 0;
    for (const [token, s] of this.sessions) {
      if (s.isExpired() || now > s.expiresAt) {
        this.destroy(token, "cleanup");
        n++;
      }
    }
    // Xoá bucket IP đã no và idle > 5 phút
    for (const [ip, b] of this.ipBucket) {
      if (b.remaining >= b.capacity && b.idleMs > 5 * 60_000) {
        this.ipBucket.delete(ip);
      }
    }
    if (n > 0) SecurityLog.info("CLEANUP", `Đã xoá ${n} session hết hạn`);
  }

  _register(session) {
    this.sessions.set(session.token, session);
    if (!this.ipIndex.has(session.ip)) this.ipIndex.set(session.ip, new Set());
    this.ipIndex.get(session.ip).add(session.token);
  }

  /* ---------- Middleware ---------- */
  /**
   * Trả về:
   *   - null                     : cho phép đi tiếp (ctx đã được gắn session)
   *   - { status, data }         : chặn request (rate limit / binding fail)
   */
  middleware() {
    const self = this;
    return async function securityMiddleware(ctx) {
      const req = ctx.req;
      const res = ctx.res;

      const ip = self.getClientIp(req);
      const fp = self.fingerprintOf(req);

      /* 1) Rate limit theo IP */
      const bucket = self._getIpBucket(ip);
      if (!bucket.tryConsume(1)) {
        SecurityLog.warn("RATE LIMIT — từ chối request", {
          ip,
          path:      ctx.path,
          method:    ctx.method,
          remaining: bucket.remaining,
        });
        return {
          status: 429,
          data: {
            status:     "error",
            message:    "Quá nhiều yêu cầu. Vui lòng thử lại sau.",
            retryAfter: 1,
            remaining:  bucket.remaining,
            capacity:   bucket.capacity,
          },
        };
      }

      /* 2) Đọc token */
      let token   = self.readToken(req);
      let session = token ? self.get(token) : null;

      if (token && !session) {
        SecurityLog.error("TOKEN không tồn tại / đã hết hạn", {
          token: token.slice(0, 16) + "...",
          ip,
          path:  ctx.path,
        });
      }

      /* 3) Nếu chưa có session -> tạo ngẫu nhiên (ANON) cho request này */
      if (!session) {
        session = self.create(req, { authenticated: false });
        token   = session.token;
      }

      /* 4) Nếu đã login -> kiểm tra ràng buộc IP + Device */
      if (session.authenticated) {
        const check = session.verifyBinding({ ip, fingerprint: fp });
        if (!check.ok) {
          SecurityLog.error("SESSION BINDING FAILED — nghi vấn chiếm phiên", {
            token:               session.token.slice(0, 16) + "...",
            userId:              session.userId,
            reason:              check.reason,
            ip,                  expectedIp: session.ip,
            fingerprint:         fp,
            expectedFingerprint: session.fingerprint,
          });
          self.destroy(session.token, `binding_${check.reason}`);
          return {
            status: 401,
            data: {
              status:  "error",
              message: "Phiên làm việc không hợp lệ (sai thiết bị hoặc IP).",
              code:    check.reason,
            },
          };
        }
      }

      /* 5) Gia hạn + gắn vào ctx */
      session.touch();
      ctx.session   = session;
      ctx.token     = session.token;
      ctx.ip        = ip;
      ctx.fingerprint = fp;
      ctx.rateLimit = {
        capacity:  bucket.capacity,
        remaining: bucket.remaining,
      };

      /* 6) Headers + Cookie phản hồi */
      if (res && typeof res.setHeader === "function") {
        res.setHeader("X-Session-Token",     session.token);
        res.setHeader("X-Session-Anon",      session.authenticated ? "0" : "1");
        res.setHeader("X-RateLimit-Limit",   String(bucket.capacity));
        res.setHeader("X-RateLimit-Remaining", String(bucket.remaining));

        const maxAge = Math.floor((session.authenticated ? session.ttl : self.anonTtl) / 1000);
        const cookieAttrs = [
          `${self.cookieName}=${encodeURIComponent(session.token)}`,
          "Path=/",
          "HttpOnly",
          "SameSite=Strict",
          `Max-Age=${maxAge}`,
        ];
        res.setHeader("Set-Cookie", cookieAttrs.join("; "));
      }

      /* 7) Log đặc biệt cho TOKEN + SESSION */
      SecurityLog.token("Request OK", {
        ip,
        method:        ctx.method,
        path:          ctx.path,
        token:         session.token.slice(0, 16) + "...",
        authenticated: session.authenticated,
        remaining:     bucket.remaining,
      });

      return null; // cho đi tiếp
    };
  }

  /** Bọc cho route cần login */
  requireAuth() {
    return function requireAuth(ctx) {
      const s = ctx.session;
      if (!s || !s.authenticated) {
        SecurityLog.warn("requireAuth — từ chối request chưa login", {
          ip:   ctx.ip,
          path: ctx.path,
        });
        return {
          status: 401,
          data: {
            status:  "error",
            message: "Yêu cầu đăng nhập.",
          },
        };
      }
      return null;
    };
  }

  stats() {
    return {
      sessions: this.sessions.size,
      ips:      this.ipIndex.size,
      buckets:  this.ipBucket.size,
      capacity: this.capacity,
      refillPerSec: this.refillPerSec,
    };
  }
}

module.exports = {
  Security,
  Session,
  TokenBucket,
  DeviceFingerprint,
  SecurityLog,
};