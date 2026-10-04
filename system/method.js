// medthod.js - Xử lý method tập trung (CommonJS)

class Medthod {
  // Bộ nhớ tạm để dọn dẹp định kỳ
  static MemoryClean = {};

  constructor({ params } = {}) {
    const p = params || {};

    // Thông tin method & dữ liệu đầu vào
    this.RecoMedthod = (p.medthod || p.method || "GET").toUpperCase();
    this.url = p.url || "/";
    this.query = p.query || {};
    this.body = p.body || {};
    this.headers = p.headers || {};
    this.timeout = p.timeout || 60000;

    // Key định danh cho entry trong MemoryClean
    this.key = `${this.RecoMedthod}_${Date.now()}_${Math.random()
      .toString(36)
      .slice(2, 8)}`;

    Medthod.MemoryClean[this.key] = {
      method: this.RecoMedthod,
      url: this.url,
      createdAt: Date.now(),
      payload: null,
    };

    // Tự động dọn entry sau timeout
    this.#autoClean(this.key);
  }

  // Private: tự xoá sau timeout
  #autoClean(key) {
    const t = setTimeout(() => {
      delete Medthod.MemoryClean[key];
    }, this.timeout);
    // Không giữ event loop sống chỉ vì timer này
    if (typeof t.unref === "function") t.unref();
  }

  // Dọn toàn bộ entry đã hết hạn
  static cleanExpired(timeout = 60000) {
    const now = Date.now();
    for (const k in Medthod.MemoryClean) {
      if (now - Medthod.MemoryClean[k].createdAt >= timeout) {
        delete Medthod.MemoryClean[k];
      }
    }
  }

  // Ghi payload vào bộ nhớ tạm
  #save(result) {
    if (Medthod.MemoryClean[this.key]) {
      Medthod.MemoryClean[this.key].payload = result;
    }
    return result;
  }

  // ---- Các handler theo method ----

  do_GET() {
    const result = {
      ok: true,
      method: "GET",
      key: this.key,
      url: this.url,
      query: this.query,
      message: "GET request handled",
      timestamp: new Date().toISOString(),
    };
    return this.#save(result);
  }

  do_POST() {
    if (!this.body || Object.keys(this.body).length === 0) {
      return {
        ok: false,
        method: "POST",
        key: this.key,
        status: 400,
        error: "Body rỗng, không có dữ liệu để xử lý",
      };
    }

    const result = {
      ok: true,
      method: "POST",
      key: this.key,
      url: this.url,
      body: this.body,
      receivedAt: new Date().toISOString(),
      message: "POST request handled",
    };
    return this.#save(result);
  }

  do_PUT() {
    const id = this.query.id || this.body.id;
    if (!id) {
      return { ok: false, method: "PUT", status: 400, error: "Thiếu id để cập nhật" };
    }

    const result = {
      ok: true,
      method: "PUT",
      key: this.key,
      id,
      body: this.body,
      message: "PUT request handled",
    };
    return this.#save(result);
  }

  do_DELETE() {
    const id = this.query.id || this.body.id;
    if (!id) {
      return { ok: false, method: "DELETE", status: 400, error: "Thiếu id để xoá" };
    }

    const result = {
      ok: true,
      method: "DELETE",
      key: this.key,
      id,
      message: "DELETE request handled",
    };
    return this.#save(result);
  }

  // Dispatcher
  handle() {
    switch (this.RecoMedthod) {
      case "GET":    return this.do_GET();
      case "POST":   return this.do_POST();
      case "PUT":    return this.do_PUT();
      case "DELETE": return this.do_DELETE();
      default:
        return {
          ok: false,
          status: 405,
          error: `Method không hỗ trợ: ${this.RecoMedthod}`,
          supported: ["GET", "POST", "PUT", "DELETE"],
        };
    }
  }
}

module.exports = Medthod;