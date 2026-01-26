# 🚀 Swagger Authentication - Simple Steps

## ✅ The Solution is Simple!

Cookies **ARE** being set automatically, but Swagger UI **CANNOT** automatically read them for authorization. You need to **manually copy-paste** the tokens.

## 📋 Step-by-Step Guide

### Step 1: Start Server
```bash
pnpm start:dev
```

### Step 2: Open Swagger UI
Go to: `http://localhost:3000/api-docs`

### Step 3: Login

1. Find **POST /auth/login** endpoint
2. Click **"Try it out"**
3. Enter your credentials:
   ```json
   {
     "emailOrUsername": "test@example.com",
     "password": "password123"
   }
   ```
4. Click **"Execute"**

### Step 4: Get Your Tokens

After successful login, you'll see tokens in **3 places**:

#### Option A: From Response Body (Easiest)
```json
{
  "access_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
  "refresh_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
  "user": { ... }
}
```
📋 **Copy these tokens!**

#### Option B: From Browser Console (Automatic)
1. Press **F12** to open DevTools
2. Go to **Console** tab
3. You'll see a green message with your tokens:
   ```
   🎉 LOGIN SUCCESSFUL - Cookies Detected!
   ✅ Access Token: eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...
   ✅ Refresh Token: eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...
   ```
4. Run `setSwaggerTokens()` to see them again anytime

#### Option C: From Response Headers
Look for:
- `x-access-token`
- `x-refresh-token`

### Step 5: Authorize in Swagger

1. **Scroll to the top** of Swagger UI
2. Click the **🔓 Authorize** button (or any lock icon)
3. You'll see 2 fields:

#### For JWT-auth (Access Token):
- **Value:** Paste your `access_token` 
- Click **"Authorize"**

#### For refresh-token (Optional):
- **Value:** Paste your `refresh_token`
- Click **"Authorize"**

4. Click **"Close"**

### Step 6: Test Protected Endpoints

Now try any protected endpoint, for example:
- **GET /auth/me**
- **GET /auth/sessions**
- **PUT /auth/profile**

They should all work! 🎉

## 🔍 Verify Cookies Are Set

### In Browser DevTools:
1. Press **F12**
2. Go to **Application** tab
3. Expand **Cookies** → `http://localhost:3000`
4. You should see:
   - ✅ `access_token`
   - ✅ `refresh_token`

### In Console:
```javascript
// See all cookies
document.cookie

// Display tokens nicely
setSwaggerTokens()
```

## 💡 Why Can't Swagger Auto-Read Cookies?

Swagger UI runs in an iframe, and for security reasons:
- It **CANNOT** automatically read cookies and set them as Authorization headers
- You **MUST** manually copy-paste the tokens
- This is a Swagger UI limitation, not a bug in our code

## ✅ What's Working:

1. ✅ Cookies **ARE** being set after login
2. ✅ Tokens **ARE** stored in browser
3. ✅ Backend **CAN** read cookies for authentication
4. ✅ Regular API calls from frontend **WILL** automatically send cookies

Only Swagger UI requires manual copy-paste!

## 🔄 Token Refresh

When your access token expires (after 15 minutes):

### Method 1: Manual Refresh
1. Call **POST /auth/refresh-token**
2. Paste your current `refresh_token` in the body
3. Get new tokens
4. Update Swagger authorization with new tokens

### Method 2: From Cookies (Automatic in Frontend)
Frontend apps automatically send cookies, so they'll get new tokens via the `OptionalJwtGuard`.

## 🌐 Frontend Integration (React/Next.js)

In your actual frontend app, cookies work automatically:

```javascript
// Login
await fetch('http://localhost:3000/auth/login', {
  method: 'POST',
  headers: { 'Content-Type': 'application/json' },
  credentials: 'include', // Important!
  body: JSON.stringify({ emailOrUsername, password }),
});

// Protected request - cookies sent automatically
await fetch('http://localhost:3000/auth/me', {
  credentials: 'include', // Cookies sent automatically
});
```

No manual token management needed in frontend! 🎊

## 🐛 Troubleshooting

### "No cookies found" in console?
- Make sure login was successful (check response status)
- Refresh the page after login
- Check if cookies are blocked in browser settings

### "Unauthorized" error on protected routes?
- Make sure you've clicked **Authorize** and pasted the tokens
- Check if token expired (access token = 15 min)
- Try refreshing your tokens

### Tokens not showing in console?
- Refresh the Swagger page
- Run `setSwaggerTokens()` in console manually

## 📝 Quick Reference

| Action | Command/Step |
|--------|--------------|
| See current tokens | Run `setSwaggerTokens()` in console |
| View cookies | DevTools → Application → Cookies |
| Authorize Swagger | Click 🔓 → Paste tokens → Authorize |
| Refresh tokens | POST /auth/refresh-token |
| Logout | POST /auth/logout (clears cookies) |

## 🎯 Summary

1. **Login** → Cookies set automatically ✅
2. **Copy tokens** from response/console 📋
3. **Paste in Swagger** Authorize dialog 🔓
4. **Test endpoints** 🚀

This is the **correct workflow** for Swagger UI!

---

**Remember:** Cookies work automatically in real applications. Manual copy-paste is only needed for Swagger UI testing!
