# 🚀 How to Test Cookie Authentication in Swagger

## ✅ Changes Made

1. **Non-HttpOnly Cookies in Development**: Cookies are now accessible via JavaScript in development mode for Swagger compatibility
2. **CORS with Credentials**: Enabled CORS with credentials support
3. **Response Headers**: Tokens are also sent in response headers (`X-Access-Token`, `X-Refresh-Token`)
4. **Auto Cookie Helper**: JavaScript helper to automatically set Swagger authorization from cookies

## 📋 Testing Steps

### Method 1: Automatic Cookie Detection (Recommended)

1. **Start the server**:
   ```bash
   pnpm start:dev
   ```

2. **Open Swagger UI**:
   ```
   http://localhost:3000/api-docs
   ```

3. **Login**:
   - Go to `POST /auth/login`
   - Click "Try it out"
   - Enter credentials:
     ```json
     {
       "emailOrUsername": "your-email@example.com",
       "password": "your-password"
     }
     ```
   - Click "Execute"

4. **Check Cookies** (F12 → Application → Cookies):
   - ✅ `access_token` should be set
   - ✅ `refresh_token` should be set

5. **Verify Auto-Authorization**:
   - Open Browser Console (F12)
   - You should see:
     ```
     🔧 Swagger Cookie Helper loaded
     🍪 Cookies found! Auto-setting Swagger authorization...
     ✅ Access token set in Swagger UI
     ✅ Refresh token set in Swagger UI
     ```

6. **Test Protected Endpoint**:
   - Try `GET /auth/me`
   - Should work without manual authorization! 🎉

### Method 2: Manual Authorization (Copy from Response)

1. **Login via Swagger**
2. **Check Response**:
   - Copy `access_token` from response body
   - Copy `refresh_token` from response body

3. **Click Authorize 🔓**:
   - **JWT-auth**: Paste access token (without "Bearer")
   - **refresh-token**: Paste refresh token
   - Click "Authorize"

4. **Test endpoints** - they should work!

### Method 3: Copy from Response Headers

After login, check **Response Headers**:
- `x-access-token`: Your access token
- `x-refresh-token`: Your refresh token

Copy these and use in Authorization dialogs.

## 🔍 Verify Cookies are Working

### Check in Browser DevTools:

1. **F12** → **Application** → **Cookies** → `http://localhost:3000`

2. You should see:
   ```
   Name: access_token
   Value: eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...
   Domain: localhost
   Path: /
   Expires: (15 minutes from now)
   HttpOnly: ❌ (false in development)
   Secure: ❌ (false in development)
   SameSite: Lax
   ```

   ```
   Name: refresh_token
   Value: eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...
   Domain: localhost
   Path: /
   Expires: (7 days from now)
   HttpOnly: ❌ (false in development)
   Secure: ❌ (false in development)
   SameSite: Lax
   ```

### Test Cookie-based Request:

Open browser console and run:
```javascript
// Check if cookies are set
document.cookie

// Make authenticated request using cookies
fetch('http://localhost:3000/auth/me', {
  credentials: 'include'
})
  .then(r => r.json())
  .then(data => console.log('User:', data));
```

## 🎯 What Happens After Login

```
1. POST /auth/login
   ↓
2. Server returns:
   - Response Body: { access_token, refresh_token, user }
   - Response Headers: X-Access-Token, X-Refresh-Token
   - Set-Cookie: access_token=..., refresh_token=...
   ↓
3. Browser automatically stores cookies
   ↓
4. swagger-helper.js reads cookies
   ↓
5. Automatically calls Swagger UI authorization
   ↓
6. All subsequent requests include cookies automatically!
```

## 🔧 Troubleshooting

### Cookies not appearing?

1. **Check Browser Console** for errors
2. **Verify CORS is enabled** (check Network tab)
3. **Make sure you're on** `http://localhost:3000/api-docs` (not different domain)
4. **Clear browser cache** and cookies, try again

### Swagger not auto-authorizing?

1. **Refresh the page** after login
2. **Check console** for swagger-helper.js errors
3. **Manually authorize** using tokens from response body

### Still not working?

1. **Copy tokens** from login response
2. Click **🔓 Authorize** buttons
3. Paste tokens manually
4. This should always work!

## 🌟 Benefits

✅ **No manual token management** - Login once, use everywhere
✅ **Automatic refresh** - Tokens auto-update in cookies
✅ **Better UX** - Similar to how real web apps work
✅ **Swagger compatible** - Works in Swagger UI too
✅ **Multiple methods** - Cookies, Headers, and Manual all supported

## 📝 Note for Production

In **production** (`NODE_ENV=production`):
- Cookies will be `httpOnly: true` (more secure)
- Cookies will be `secure: true` (HTTPS only)
- You'll need to use Authorization headers instead

For production testing, use the manual authorization method or API clients like Postman/Insomnia.
