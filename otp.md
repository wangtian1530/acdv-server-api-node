## 🔐 OTP — Flow mới (password → temp token)

### Request OTP (cần password)

**`POST /otp/request`** 🔒

```json
{
  "password": "pw123456"
}
```

**Response 201:**
```json
{
  "status": "success",
  "message": "Đã sinh OTP và token tạm",
  "data": {
    "otp_id": 3,
    "otp": "42",
    "token": "otp_3a8f1c9b2e4d5f6a7b8c9d0e1f2a3b4c5d6e7f8a",
    "expires_in": 300
  }
}
```
> - `otp` (thực tế gửi qua email/SMS, demo trả luôn)
> - `token` temp — **KHÁC** session token
> - OTP cũ của user tự động bị vô hiệu

### Verify OTP (dùng temp token, KHÔNG cần login)

**`POST /otp/verify`**

```json
{
  "token": "otp_3a8f1c9b2e4d5f6a7b8c9d0e1f2a3b4c5d6e7f8a",
  "otp": "42"
}
```

**Response 200:**
```json
{
  "status": "success",
  "message": "Xác thực OTP thành công",
  "id": 3
}
```

---

## 👑 Admin — chỉ ẨN, không XÓA

### Ẩn project

**`POST /projects/:id/hide`** 🔒 (admin only)

**Response 200:**
```json
{ "status": "success", "message": "Đã ẩn project" }
```

**Response 403 (không phải admin):**
```json
{ "status": "error", "message": "Chỉ admin mới có quyền ẩn project" }
```

### Bỏ ẩn

**`POST /projects/:id/unhide`** 🔒 (admin only)

### Ẩn comment (chủ project hoặc admin)

**`POST /comments/:id/hide`** 🔒

**Response 200:**
```json
{ "status": "success", "message": "Đã ẩn bình luận" }
```

**Response 403:**
```json
{ "status": "error", "message": "Chỉ chủ project hoặc admin mới được ẩn bình luận" }
```

---

## 🚫 User không xóa được chính mình

**`DELETE /users/me`** 🔒

**Response 403:**
```json
{
  "status": "error",
  "message": "Tính năng xóa tài khoản đang tạm khóa"
}
```

---

## 🔄 Update comment (chỉ tác giả)

**`PUT /comments/:id`** 🔒

```json
{
  "context": "Đã sửa: dự án rất tiềm năng!"
}
```

**Response 403 (không phải tác giả):**
```json
{ "status": "error", "message": "Bạn không phải tác giả comment" }
```