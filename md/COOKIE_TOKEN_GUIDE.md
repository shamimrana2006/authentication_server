# 🍪 Cookie-Based Token Authentication Guide

## ✅ What's Implemented

আপনার প্রজেক্টে এখন **automatic cookie-based token management** সাপোর্ট করা হচ্ছে Swagger সহ!

## 🎯 How It Works

### 1. **Login করার সময়**
```bash
POST /auth/login
{
  "emailOrUsername": "user@example.com",
  "password": "password123"
}
```

**Response:**
```json
{
  "access_token": "eyJhbGc...",
  "refresh_token": "eyJhbGc...",
  "user": { ... }
}
```

**Automatically Sets Cookies:**
- `access_token` → 15 minutes validity
- `refresh_token` → 7 days validity

### 2. **Cookie Configuration**
```typescript
{
  httpOnly: true,           // JavaScript থেকে access করা যাবে না (Security)
  secure: production,       // HTTPS তে only (production এ)
  sameSite: 'lax',         // CSRF protection
  maxAge: ...              // Expiry time
}
```

### 3. **Automatic Token Usage**

এরপর যেকোনো protected endpoint call করলে:
- Cookie থেকে automatically token নেওয়া হবে
- Manual header সেট করার দরকার নেই!

```bash
GET /auth/me
# No Authorization header needed!
# Cookie automatically sent
```

## 🔐 Multi-Source Token Support

এখন token **৩ টি জায়গা থেকে** accept করা হয়:

1. **Cookie** (Automatic): `access_token` cookie
2. **Authorization Header** (Manual): `Bearer <token>`
3. **Custom Header** (Optional): `x-refresh-token`

### Priority Order:
```
Authorization Header > Cookie > Custom Header
```

## 📱 Swagger UI Usage

### Method 1: Cookie-Based (Automatic after login)
1. Swagger UI তে যান: `http://localhost:3000/api-docs`
2. **POST /auth/login** call করুন
3. ব্রাউজারে automatically cookies সেট হবে
4. এখন অন্য endpoints simply call করুন - no authorization needed!

### Method 2: Manual Authorization
1. Login করে tokens copy করুন
2. 🔓 **Authorize** buttons এ click করুন:
   - **JWT-auth**: Access Token পেস্ট করুন
   - **refresh-token**: Refresh Token পেস্ট করুন
3. **Authorize** click করুন

## 🔄 Token Refresh Flow

### Automatic (via OptionalJwtGuard):
যখন `access_token` expire হয়:
1. Cookie থেকে `refresh_token` নেয়
2. Automatically নতুন tokens generate করে
3. Response headers এ পাঠায়:
   - `x-new-access-token`
   - `x-new-refresh-token`
4. Cookies update করে

### Manual:
```bash
POST /auth/refresh-token
{
  "refreshToken": "eyJhbGc..."
}
```

## 🚪 Logout

```bash
POST /auth/logout
{
  "refreshToken": "eyJhbGc..."
}
```

**Automatically:**
- Session থেকে token delete করে
- Cookies clear করে

## 🛠️ Technical Implementation

### 1. Main.ts - Cookie Parser
```typescript
import * as cookieParser from 'cookie-parser';
app.use(cookieParser());
```

### 2. Auth Controller - Cookie Setting
```typescript
res.cookie('access_token', result.access_token, {
  httpOnly: true,
  secure: process.env.NODE_ENV === 'production',
  sameSite: 'lax',
  maxAge: 15 * 60 * 1000,
});
```

### 3. JWT Strategy - Cookie Extraction
```typescript
jwtFromRequest: ExtractJwt.fromExtractors([
  ExtractJwt.fromAuthHeaderAsBearerToken(),
  (request: Request) => request?.cookies?.access_token,
]),
```

### 4. Swagger Configuration
```typescript
.addCookieAuth('access_token', { ... })
.addCookieAuth('refresh_token', { ... })
```

## 🌐 Frontend Integration

### Browser (Automatic)
```javascript
// Cookies automatically sent with each request
fetch('http://localhost:3000/auth/me', {
  credentials: 'include'  // Important!
});
```

### React/Next.js Example
```javascript
const response = await fetch('/auth/login', {
  method: 'POST',
  headers: { 'Content-Type': 'application/json' },
  credentials: 'include', // Send cookies
  body: JSON.stringify({ emailOrUsername, password }),
});

// Cookies automatically stored and sent in subsequent requests
const user = await fetch('/auth/me', {
  credentials: 'include'
});
```

### Axios Example
```javascript
import axios from 'axios';

axios.defaults.withCredentials = true;

await axios.post('/auth/login', { emailOrUsername, password });
// Cookies auto-stored

await axios.get('/auth/me');
// Cookies auto-sent
```

## 🔒 Security Features

✅ **HttpOnly Cookies**: JavaScript থেকে access করা যায় না (XSS protection)
✅ **Secure Flag**: Production এ শুধু HTTPS
✅ **SameSite**: CSRF attack protection
✅ **Token Rotation**: Refresh token use করলে নতুন token issue হয়
✅ **Session Tracking**: Database এ track করা হয়
✅ **Expiry Management**: Automatic cleanup

## 🧪 Testing

### 1. Login Test (Swagger UI)
```
1. Go to: http://localhost:3000/api-docs
2. Try: POST /auth/login
3. Check: Browser DevTools → Application → Cookies
4. Verify: access_token and refresh_token cookies
```

### 2. Protected Route Test
```
1. After login, call: GET /auth/me
2. No manual authorization needed
3. Should return user data
```

### 3. Logout Test
```
1. Call: POST /auth/logout
2. Check DevTools → Cookies should be cleared
3. Try: GET /auth/me → Should return null user
```

## 📋 Environment Variables

Make sure you have:
```env
NODE_ENV=development
JWT_SECRET=your-secret-key
```

## 🎉 Benefits

1. ✅ **Better UX**: No manual token management needed
2. ✅ **Security**: HttpOnly cookies prevent XSS
3. ✅ **Swagger Integration**: Works seamlessly in Swagger UI
4. ✅ **Multi-platform**: Works with web browsers automatically
5. ✅ **Backward Compatible**: Still supports manual Authorization headers

## 🔗 Endpoints Summary

| Endpoint | Cookie Set | Cookie Required | Notes |
|----------|-----------|-----------------|-------|
| `POST /auth/login` | ✅ Yes | ❌ No | Sets both tokens |
| `POST /auth/refresh-token` | ✅ Yes | ❌ No | Updates both tokens |
| `POST /auth/logout` | ❌ Clears | ✅ Yes | Removes cookies |
| `GET /auth/me` | ❌ No | ✅ Yes (auto) | Auto-refresh support |
| `PUT /auth/profile` | ❌ No | ✅ Yes (auto) | Protected route |
| All protected routes | ❌ No | ✅ Yes (auto) | Auto token from cookie |

## 🚀 Quick Start

1. Start server: `pnpm start:dev`
2. Open Swagger: `http://localhost:3000/api-docs`
3. Login via Swagger UI
4. Enjoy automatic cookie-based auth! 🎊

---

**Note**: Cookie-based auth works best in browser environments. For mobile apps or non-browser clients, continue using Authorization headers.
