## 👑 Ma trận phân quyền

```
                    │ GUEST │ USER  │ OWNER │ ADMIN │
────────────────────┼───────┼───────┼───────┼───────┤
Xem user khác       │   ❌  │   ❌  │   ❌  │   ❌  │
Xem user /me        │   ❌  │   ✅  │   ✅  │   ✅  │
Sửa user /me        │   ❌  │   ✅  │   ✅  │   ✅  │
Xóa user /me        │   ❌  │   ❌  │   ❌  │   ❌  │
────────────────────┼───────┼───────┼───────┼───────┤
Xem profile /me     │   ❌  │   ✅  │   ✅  │   ✅  │
Update profile /me  │   ❌  │   ✅  │   ✅  │   ✅  │
Delete profile      │   ❌  │   ❌  │   ❌  │   ❌  │
────────────────────┼───────┼───────┼───────┼───────┤
Tạo project         │   ❌  │   ✅  │   ✅  │   ✅  │
Sửa project         │   ❌  │   ❌  │   ✅  │   ❌  │
Xóa project (hard)  │   ❌  │   ❌  │   ✅  │   ❌  │
Ẩn project (soft)   │   ❌  │   ❌  │   ❌  │   ✅  │
────────────────────┼───────┼───────┼───────┼───────┤
Tạo comment         │   ❌  │   ✅  │   ✅  │   ✅  │
Sửa comment         │   ❌  │   tác giả │ tác giả │ tác giả │
Xóa comment (hard)  │   ❌  │   tác giả │ tác giả │ tác giả │
Ẩn comment (soft)   │   ❌  │   ❌  │ chủ proj │ ✅  │
────────────────────┼───────┼───────┼───────┼───────┤
Request OTP (pw)    │   ❌  │   ✅  │   ✅  │   ✅  │
Verify OTP (token)  │   ✅  │   ✅  │   ✅  │   ✅  │
```

---

## 🔄 Flow OTP mới

```
User                          Server
 │                              │
 │  POST /otp/request           │
 │  { password: "..." }         │
 │─────────────────────────────►│
 │                              │ 1. verifyPassword(userId, password)
 │                              │ 2. Deactivate OTP cũ
 │                              │ 3. genOtp2Digit() → "42"
 │                              │ 4. genTempToken() → "otp_..."
 │                              │ 5. INSERT OTPAuthUser(active=1, OTP, token)
 │                              │
 │  { otp, token, expires_in }  │
 │◄─────────────────────────────│
 │                              │
 │  (thực tế: OTP gửi qua SMS)  │
 │                              │
 │  POST /otp/verify            │
 │  { token, otp }              │
 │─────────────────────────────►│
 │                              │ 1. SELECT ... WHERE token=? AND OTP=? AND active=1
 │                              │ 2. UPDATE active=0
 │                              │
 │  { status: "success" }       │
 │◄─────────────────────────────│
```

**Đặc điểm:**
- Password **chỉ dùng để sinh OTP** — KHÔNG lưu session mới
- Temp token **tách biệt** session token
- Verify OTP **không cần login** — token tạm đã là auth
- OTP cũ tự động bị vô hiệu khi request mới