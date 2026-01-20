# Token Refresh Flow Implementation

## Overview
The `/auth/me` endpoint now implements an intelligent token refresh mechanism that handles all possible token states automatically.

## How It Works

### Token Flow Scenarios

#### 1. ✅ Both Tokens Valid
- **Condition**: Access token valid AND Refresh token valid
- **Action**: Return user data normally
- **Response**: User data with `tokensRefreshed: false`

#### 2. 🔄 Access Invalid, Refresh Valid
- **Condition**: Access token expired/invalid AND Refresh token valid
- **Action**: Auto-refresh both tokens (token rotation)
- **Response**: 
  - User data with `tokensRefreshed: true`
  - New tokens in response headers: `X-New-Access-Token`, `X-New-Refresh-Token`
  - Cookies updated automatically

#### 3. 🔄 Access Valid, Refresh Invalid
- **Condition**: Access token valid AND Refresh token expired/invalid
- **Action**: Generate new refresh token (keep session alive)
- **Response**: 
  - User data with `tokensRefreshed: true`
  - New tokens in response headers
  - Cookies updated automatically

#### 4. ❌ Both Tokens Invalid
- **Condition**: Access token invalid AND Refresh token invalid
- **Action**: Clear cookies and force logout
- **Response**: 
  ```json
  {
    "success": false,
    "message": "Not authenticated - both tokens invalid",
    "user": null
  }
  ```

## Implementation Details

### Frontend Integration

#### Sending Tokens
Frontend should send both tokens on every request to `/auth/me`:

```javascript
// Option 1: Using Headers (Recommended for SPA/Mobile Apps)
fetch('http://localhost:3000/auth/me', {
  headers: {
    'Authorization': `Bearer ${accessToken}`,
    'X-Refresh-Token': refreshToken
  },
  credentials: 'include' // For cookie support
})

// Option 2: Using Cookies (Automatic)
fetch('http://localhost:3000/auth/me', {
  credentials: 'include' // Cookies sent automatically
})
```

#### Handling Response
```javascript
const response = await fetch('http://localhost:3000/auth/me', {
  headers: {
    'Authorization': `Bearer ${accessToken}`,
    'X-Refresh-Token': refreshToken
  },
  credentials: 'include'
});

const data = await response.json();

// Check if tokens were refreshed
if (data.tokensRefreshed) {
  const newAccessToken = response.headers.get('X-New-Access-Token');
  const newRefreshToken = response.headers.get('X-New-Refresh-Token');
  
  // Update stored tokens
  localStorage.setItem('access_token', newAccessToken);
  localStorage.setItem('refresh_token', newRefreshToken);
  
  console.log('Tokens automatically refreshed!');
}

// Check authentication status
if (!data.success || !data.user) {
  // User is logged out - redirect to login
  window.location.href = '/login';
} else {
  // User is authenticated
  console.log('User:', data.user);
}
```

### Backend Components

#### OptionalJwtGuard
Located at: [src/common/optional-auth.guard.ts](src/common/optional-auth.guard.ts)

The guard implements the core logic:
1. Extracts tokens from headers and cookies
2. Validates access token
3. Validates refresh token
4. Handles all 4 scenarios
5. Attaches new tokens to response headers/cookies

#### Auth Controller
The `/auth/me` endpoint at [src/auth/auth.controller.ts](src/auth/auth.controller.ts#L73-L95):
- Uses `OptionalJwtGuard` for automatic token refresh
- Returns user data or null based on authentication state
- Includes `tokensRefreshed` flag in response

#### Auth Service
Token generation methods at [src/auth/auth.service.ts](src/auth/auth.service.ts):
- `generateTokens(user)`: Creates new access + refresh tokens
- `refreshToken(refreshToken)`: Rotates tokens (deletes old, creates new)
- `validateRefreshToken(userId, refreshToken)`: Validates refresh token in database

## Token Configuration

### Current Settings (for testing)
```typescript
// Access Token: 10 seconds (very short for testing)
expiresIn: "10s"

// Refresh Token: 20 seconds (very short for testing)
expiresIn: "20s"
```

### Production Settings (recommended)
Update in [src/auth/auth.service.ts](src/auth/auth.service.ts#L156-L167):
```typescript
// Access Token: 15 minutes
expiresIn: `${accessTokenExpiration}m`

// Refresh Token: 7 days
expiresIn: `${refreshTokenExpiration}d`
```

## Testing

### Test File
Use [test-token-refresh.http](test-token-refresh.http) to test all scenarios.

### Manual Testing Steps

1. **Login and get tokens**
   ```bash
   POST /auth/login
   ```

2. **Test normal flow (both valid)**
   ```bash
   GET /auth/me
   # Immediately after login
   ```

3. **Test access token expiry (wait 10s)**
   ```bash
   GET /auth/me
   # After 10 seconds - should auto-refresh
   ```

4. **Test both expired (wait 20s)**
   ```bash
   GET /auth/me
   # After 20 seconds - should return user: null
   ```

### Expected Responses

#### Success with valid tokens:
```json
{
  "success": true,
  "user": {
    "id": "...",
    "email": "test@example.com",
    "name": "Test User"
  },
  "tokensRefreshed": false
}
```

#### Success with auto-refresh:
```json
{
  "success": true,
  "user": {
    "id": "...",
    "email": "test@example.com",
    "name": "Test User"
  },
  "tokensRefreshed": true
}
```
**Headers:**
- `X-New-Access-Token`: new_access_token
- `X-New-Refresh-Token`: new_refresh_token

#### Failed authentication:
```json
{
  "success": false,
  "message": "Not authenticated - both tokens invalid",
  "user": null
}
```

## Security Features

1. **Token Rotation**: When refreshing, old refresh token is deleted and new one created
2. **Database Validation**: Refresh tokens validated against database sessions
3. **Automatic Cleanup**: Invalid tokens are cleared from cookies
4. **Secure Cookies**: 
   - `httpOnly: false` in development (for Swagger testing)
   - `httpOnly: true` recommended for production
   - `secure: true` in production (HTTPS only)
   - `sameSite: 'lax'` for CSRF protection

## Troubleshooting

### Tokens not refreshing
- Check browser console for new token headers
- Verify frontend sends both tokens
- Check cookie settings (credentials: 'include')

### Still getting 401 errors
- Verify tokens are being sent in correct headers
- Check JWT_SECRET in .env file
- Verify database sessions table has valid entries

### Cookies not working
- Ensure cookie-parser is installed
- Check browser allows cookies
- Verify domain/path settings match

## Migration from Old Implementation

### Before (Manual Refresh):
```javascript
// Frontend had to manually call /auth/refresh-token
if (response.status === 401) {
  const newTokens = await refreshTokens();
  // Retry original request
}
```

### After (Automatic):
```javascript
// Just call /auth/me - refreshing happens automatically
const response = await fetch('/auth/me');
if (response.headers.get('X-New-Access-Token')) {
  // Update stored tokens
  updateTokens(response.headers);
}
```

## Benefits

✅ **Seamless UX**: Users stay logged in without interruption  
✅ **Automatic**: No manual refresh token calls needed  
✅ **Secure**: Token rotation prevents token reuse  
✅ **Flexible**: Works with both headers and cookies  
✅ **Transparent**: Frontend knows when tokens were refreshed  
✅ **Logout Detection**: Automatically detects when user should logout
