## 🔐 Chính sách mới (v6)

| Resource | Create | Read | Update | Delete (hard) | Hide (soft) |
|----------|:---:|:---:|:---:|:---:|:---:|
| **User** | public | **chỉ `/me`** | self (`/me`) | ❌ **CẤM** | — |
| **Profile** | self (upsert) | self (`/me`) | self (`/me`) | ❌ **không có route** | — |
| **Project** | any logged | public (non-hidden) | **owner** | **owner** | **admin** |
| **Comment** | any logged | public (non-hidden) | **author** | **author** | **chủ project / admin** |
| **OTP** | self (`/me`) | self (`/me`) | — | self | — |

### 🎯 Quy tắc cốt lõi

1. **Không có route xem user khác** — chỉ `/users/me`.
2. **Không xóa được user** — `DELETE /users/me` luôn 403.
3. **Profile luôn UPDATE**, không bao giờ xóa.
4. **Project** — chủ sở hữu có quyền SỬA/XÓA. Admin **chỉ ẨN**.
5. **Comment** — author sửa/xóa. Chủ project **chỉ ẨN** comment của người khác trong project của mình.
6. **Xóa là HARD DELETE** (xóa thật khỏi DB).
7. **OTP** — request cần password, sinh temp token riêng. Verify bằng temp token.

### 📡 Routes tổng hợp

```
AUTH
  POST   /auth/login
  POST   /auth/logout
  GET    /auth/me 🔒

USER  (chỉ /me)
  GET    /users/me 🔒
  PUT    /users/me 🔒
  POST   /users                     (đăng ký — public)
  DELETE /users/me 🔒               → 403

PROFILE  (luôn /me, không DELETE)
  GET    /profiles/me 🔒
  PUT    /profiles/me 🔒

PROJECT
  GET    /projects                  (public, hidden=0)
  GET    /projects/me 🔒            (kể cả hidden)
  GET    /projects/:id              (public nếu không hidden)
  POST   /projects 🔒
  PUT    /projects/:id 🔒           (owner only)
  DELETE /projects/:id 🔒           (owner only, hard)
  POST   /projects/:id/hide 🔒      (admin only)
  POST   /projects/:id/unhide 🔒    (admin only)

COMMENT
  GET    /projects/:id/comments
  POST   /projects/:id/comments 🔒
  PUT    /comments/:id 🔒           (author only)
  DELETE /comments/:id 🔒           (author only, hard)
  POST   /comments/:id/hide 🔒      (project owner / admin)
  POST   /comments/:id/unhide 🔒    (project owner / admin)

OTP
  POST   /otp/request 🔒            (body: { password })  ← cần password
  POST   /otp/verify                (body: { token, otp }) ← public
  GET    /otp/me 🔒
  DELETE /otp/:id 🔒                (owner only)
```
