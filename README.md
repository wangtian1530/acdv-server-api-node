## 🔐 Chính sách mới (v6)

| Resource | Create | Read | Update | Delete (hard) | Hide (soft) |
|----------|:---:|:---:|:---:|:---:|:---:|
| **User** | public | **chỉ `/me`** | self (`/me`) | ❌ **CẤM** | — |
| **Profile** | self (upsert) | self (`/me`) | self (`/me`) | ❌ **không có route** | — |
| **Project** | any logged | public (non-hidden) | **owner** | **owner** | **admin** |
| **Comment** | any logged | public (non-hidden) | **author** | **author** | **chủ project / admin** |
| **OTP** | self (`/me`) | self (`/me`) | — | self | — |

### 🎯 Quy tắc cốt lõi

1. **Không có route xem user khác** — chỉ `/api/users/me`.
2. **Không xóa được user** — `DELETE /api/users/me` luôn 403.
3. **Profile luôn UPDATE**, không bao giờ xóa.
4. **Project** — chủ sở hữu có quyền SỬA/XÓA. Admin **chỉ ẨN**.
5. **Comment** — author sửa/xóa. Chủ project **chỉ ẨN** comment của người khác trong project của mình.
6. **Xóa là HARD DELETE** (xóa thật khỏi DB).
7. **OTP** — request cần password, sinh temp token riêng. Verify bằng temp token.

### 📡 Routes tổng hợp

```
AUTH
  POST   /api/auth/login
  POST   /api/auth/logout
  GET    /api/auth/me 🔒

USER  (chỉ /me)
  GET    /api/users/me 🔒
  PUT    /api/users/me 🔒
  POST   /api/users                     (đăng ký — public)
  DELETE /api/users/me 🔒               → 403

PROFILE  (luôn /me, không DELETE)
  GET    /api/profiles/me 🔒
  PUT    /api/profiles/me 🔒

PROJECT
  GET    /api/projects                  (public, hidden=0)
  GET    /api/projects/me 🔒            (kể cả hidden)
  GET    /api/projects/:id              (public nếu không hidden)
  POST   /api/projects 🔒
  PUT    /api/projects/:id 🔒           (owner only)
  DELETE /api/projects/:id 🔒           (owner only, hard)
  POST   /api/projects/:id/hide 🔒      (admin only)
  POST   /api/projects/:id/unhide 🔒    (admin only)

COMMENT
  GET    /api/projects/:id/comments
  POST   /api/projects/:id/comments 🔒
  PUT    /api/comments/:id 🔒           (author only)
  DELETE /api/comments/:id 🔒           (author only, hard)
  POST   /api/comments/:id/hide 🔒      (project owner / admin)
  POST   /api/comments/:id/unhide 🔒    (project owner / admin)

OTP
  POST   /api/otp/request 🔒            (body: { password })  ← cần password
  POST   /api/otp/verify                (body: { token, otp }) ← public
  GET    /api/otp/me 🔒
  DELETE /api/otp/:id 🔒                (owner only)
```
