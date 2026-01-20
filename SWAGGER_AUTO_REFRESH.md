# Swagger Automatic Token Refresh Guide

## 🎯 What's Fixed

When tokens are refreshed automatically (e.g., when access token expires), **Swagger now auto-updates** the authorization with the new tokens!

## How It Works

### 1. **Exposed Headers in CORS**
```typescript
exposedHeaders: ['X-New-Access-Token', 'X-New-Refresh-Token']
```
This allows JavaScript to read the new token headers from responses.

### 2. **Automatic Detection**
The Swagger helper intercepts **ALL** fetch responses and checks for:
- `X-New-Access-Token` header
- `X-New-Refresh-Token` header

### 3. **Auto Re-authorization**
When new tokens are detected:
1. ✅ Cookies are automatically updated (by backend)
2. ✅ Swagger authorization is updated (by JavaScript)
3. ✅ Console shows confirmation message
4. ✅ Next request uses new tokens automatically

## Testing Steps

### Test 1: Login and Auto-Auth
1. Open Swagger UI: http://localhost:3000/api-docs
2. Open browser console (F12)
3. Execute `POST /auth/login`
4. **Check console** - should see:
   ```
   🎉 AUTO-AUTHORIZING SWAGGER...
   ✅ Access Token Set
   ✅ Refresh Token Set
   🔒 Authorize button is now LOCKED!
   ```
5. The 🔓 button should turn to 🔒

### Test 2: Automatic Token Refresh on /auth/me
1. **Wait 10 seconds** (for access token to expire)
2. Execute `GET /auth/me`
3. **Check console** - should see:
   ```
   🔄 NEW TOKENS DETECTED!
      Access Token: ✅ Updated
      Refresh Token: ✅ Updated
   🎉 Swagger authorization updated with new tokens!
   ```
4. **Check response headers** in Swagger:
   - Should see `X-New-Access-Token`
   - Should see `X-New-Refresh-Token`
5. The 🔒 button stays locked with updated tokens!

### Test 3: Verify New Tokens Work
1. Immediately execute `GET /auth/me` again
2. Should work without errors
3. No new tokens in headers (because both are still valid)

### Test 4: Complete Expiry (Both Tokens Invalid)
1. **Wait 20 seconds** (for both tokens to expire)
2. Execute `GET /auth/me`
3. Response should be:
   ```json
   {
     "success": false,
     "message": "Not authenticated - both tokens invalid",
     "user": null
   }
   ```
4. No token refresh happens
5. Need to login again

## Console Commands

Available in browser console:

### `reauthorizeSwagger()`
Manually re-authorize Swagger from cookies.
```javascript
reauthorizeSwagger()
```

### `showTokens()`
Display current tokens from cookies for manual copy-paste.
```javascript
showTokens()
```

### `clearSwaggerAuth()`
Clear Swagger authorization and cookies.
```javascript
clearSwaggerAuth()
```

## Visual Indicators

### ✅ Tokens Refreshed Successfully
```
🔄 NEW TOKENS DETECTED!
   Access Token: ✅ Updated
   Refresh Token: ✅ Updated
🎉 Swagger authorization updated with new tokens!
```

### ⚠️ No Tokens Found
```
⚠️ No tokens found in cookies
Please login first: POST /auth/login
```

### ❌ Both Tokens Invalid
No console message, but API returns:
```json
{
  "success": false,
  "user": null
}
```

## Frontend Integration

For non-Swagger frontends (React/Vue/Angular), check response headers:

```javascript
const response = await fetch('/auth/me', {
  headers: {
    'Authorization': `Bearer ${accessToken}`,
    'X-Refresh-Token': refreshToken
  },
  credentials: 'include'
});

// Check if tokens were refreshed
const newAccess = response.headers.get('X-New-Access-Token');
const newRefresh = response.headers.get('X-New-Refresh-Token');

if (newAccess && newRefresh) {
  console.log('🔄 Tokens auto-refreshed!');
  localStorage.setItem('access_token', newAccess);
  localStorage.setItem('refresh_token', newRefresh);
}

const data = await response.json();
```

## Troubleshooting

### Tokens not auto-updating in Swagger
1. Check browser console for errors
2. Verify CORS `exposedHeaders` includes the token headers
3. Check if cookies are being set (Application tab in DevTools)
4. Try `reauthorizeSwagger()` manually

### Headers not visible
Make sure CORS configuration exposes the headers:
```typescript
exposedHeaders: ['X-New-Access-Token', 'X-New-Refresh-Token']
```

### Still getting 401 errors
1. Check token expiration times (currently 10s/20s for testing)
2. Verify database has valid sessions
3. Clear cookies and login again: `clearSwaggerAuth()`

## Production Considerations

Before deploying, update token expiration in [auth.service.ts](src/auth/auth.service.ts#L156-L167):

```typescript
// Change from testing values:
expiresIn: "10s"  // Access token
expiresIn: "20s"  // Refresh token

// To production values:
expiresIn: `${accessTokenExpiration}m`   // 15 minutes
expiresIn: `${refreshTokenExpiration}d`  // 7 days
```

Also update cookie settings in production:
```typescript
httpOnly: true  // Change from false to true
secure: true    // Only over HTTPS
```
