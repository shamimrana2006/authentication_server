# Discord OAuth Backend Endpoints - সম্পূর্ণ Flow

## 📊 Discord Login Flow Diagram

```
┌─────────────────────────────────────────────────────────────────┐
│                     FRONTEND (Browser)                          │
│              http://localhost:6545/auth/socialLogin.html        │
└─────────────────────────────────────────────────────────────────┘
                              ↓
                    User clicks "Discord দিয়ে লগিন করুন"
                              ↓
┌─────────────────────────────────────────────────────────────────┐
│  STEP 1: Initiate Discord OAuth                                 │
│  ✅ GET /auth/discord (Passport AuthGuard trigger)              │
│                                                                  │
│  What happens:                                                   │
│  1. DiscordStrategy.validate() checks environment variables     │
│  2. Constructs OAuth URL with CLIENT_ID & REDIRECT_URI          │
│  3. Redirects browser to Discord authorization page             │
│                                                                  │
│  Example OAuth URL:                                              │
│  https://discord.com/oauth2/authorize?                          │
│    client_id=1464773208359305317&                               │
│    redirect_uri=http://localhost:6545/auth/discord/callback&    │
│    response_type=code&                                          │
│    scope=identify%20email&                                      │
│    state=random_state_string                                    │
└─────────────────────────────────────────────────────────────────┘
                              ↓
                    User logs in with Discord
                    User clicks "Authorize"
                              ↓
┌─────────────────────────────────────────────────────────────────┐
│  STEP 2: OAuth Callback (Discord Redirects Back)                │
│  ✅ GET /auth/discord/callback?code=XXX&state=YYY              │
│                                                                  │
│  What happens:                                                   │
│  1. Discord sends authorization code                            │
│  2. Passport intercepts request                                 │
│  3. DiscordStrategy exchanges code for access token             │
│  4. Fetches Discord user profile data                           │
│  5. Calls validate() with profile info                          │
└─────────────────────────────────────────────────────────────────┘
                              ↓
┌─────────────────────────────────────────────────────────────────┐
│  STEP 3: Process User Data                                      │
│  ✅ AuthService.discordAuthCallback(discordUserData)            │
│                                                                  │
│  What happens:                                                   │
│  1. Check if user exists (by discord ID or email)               │
│  2. If NEW user:                                                 │
│     - Generate strong password (16 chars)                       │
│     - Hash password with bcrypt                                 │
│     - Create user in database                                   │
│     - Send email with password                                  │
│  3. If EXISTING user (linking):                                  │
│     - Link discord ID to existing account                       │
│  4. Generate JWT tokens (access + refresh)                      │
│  5. Return success response                                      │
└─────────────────────────────────────────────────────────────────┘
                              ↓
┌─────────────────────────────────────────────────────────────────┐
│  STEP 4: Database Operations                                    │
│  ✅ Prisma Client CRUD                                          │
│                                                                  │
│  QUERY 1 - Check User Existence:                                │
│  SELECT * FROM "User"                                           │
│  WHERE discord = ? OR email = ?                                 │
│                                                                  │
│  QUERY 2 - Create New User (if needed):                         │
│  INSERT INTO "User" (id, email, discord, password, ...)         │
│  VALUES (?, ?, ?, ?, ...)                                       │
│                                                                  │
│  QUERY 3 - Update User (if linking):                            │
│  UPDATE "User"                                                  │
│  SET discord = ?, emailVerified = true                          │
│  WHERE id = ?                                                   │
└─────────────────────────────────────────────────────────────────┘
                              ↓
┌─────────────────────────────────────────────────────────────────┐
│  STEP 5: Email Service                                          │
│  ✅ EmailService.sendGoogleAuthPassword()                       │
│                                                                  │
│  What happens:                                                   │
│  1. Connect to SMTP server (smtp.gmail.com:587)                │
│  2. Compose welcome email with password                         │
│  3. Send to user's Discord email address                        │
│  4. Email contains:                                              │
│     - Generated password                                        │
│     - Username                                                  │
│     - Security warnings                                         │
│     - Account activation link (if needed)                       │
└─────────────────────────────────────────────────────────────────┘
                              ↓
┌─────────────────────────────────────────────────────────────────┐
│  STEP 6: Generate JWT Tokens                                    │
│  ✅ AuthService.generateTokens(user)                            │
│                                                                  │
│  What happens:                                                   │
│  1. Create access token payload:                                │
│     {                                                            │
│       sub: user.id,                                             │
│       email: user.email,                                        │
│       username: user.username,                                  │
│       iat: timestamp,                                           │
│       exp: timestamp + 1 hour                                   │
│     }                                                            │
│  2. Sign with JWT_SECRET                                        │
│  3. Create refresh token (longer expiry)                        │
│  4. Return both tokens                                          │
└─────────────────────────────────────────────────────────────────┘
                              ↓
┌─────────────────────────────────────────────────────────────────┐
│  STEP 7: Redirect to Frontend                                   │
│  ✅ res.cookie() + res.redirect()                               │
│                                                                  │
│  What happens:                                                   │
│  1. Set httpOnly cookies:                                       │
│     - Set-Cookie: accessToken=eyJhbGc...                       │
│     - Set-Cookie: refreshToken=eyJhbGc...                      │
│  2. Redirect with query parameters:                             │
│     http://localhost:3000/?                                     │
│       access_token=eyJhbGc...&                                  │
│       refresh_token=eyJhbGc...&                                 │
│       user={json_encoded_user}                                  │
└─────────────────────────────────────────────────────────────────┘
                              ↓
┌─────────────────────────────────────────────────────────────────┐
│                     FRONTEND Again                              │
│              Browser receives query parameters                  │
│              Extracts and displays user info                    │
│              Stores tokens in localStorage                      │
│              Shows JWT tokens in textarea                       │
└─────────────────────────────────────────────────────────────────┘
```

---

## 🔄 Backend Routes Called

### **1️⃣ GET /auth/discord**

**File:** `src/auth/auth.controller.ts`

```typescript
@Get('discord')
@UseGuards(AuthGuard('discord'))
async discordAuth() {
  // Passport will handle this
  // Redirects to Discord OAuth page
}
```

**Executed Code:**

- ✅ `DiscordStrategy` (passport-discord)
- ✅ Checks env variables: `DISCORD_CLIENT_ID`, `DISCORD_CLIENT_SECRET`, `DISCORD_CALLBACK_URL`
- ✅ Constructs OAuth authorization URL
- ✅ Redirects browser to Discord

---

### **2️⃣ GET /auth/discord/callback**

**File:** `src/auth/auth.controller.ts`

```typescript
@Get('discord/callback')
@UseGuards(AuthGuard('discord'))
async discordCallback(@Req() req, @Res() res) {
  const result = await this.authService.discordAuthCallback(req.user);
  res.cookie('accessToken', result.access_token, {...});
  res.cookie('refreshToken', result.refresh_token, {...});
  res.redirect(`${FRONTEND_URL}/?access_token=...&refresh_token=...`);
}
```

**Executed Code:**

- ✅ `DiscordStrategy.validate()` called automatically
- ✅ Passport exchanges code for access token
- ✅ Fetches Discord profile from API
- ✅ `AuthService.discordAuthCallback()` processes the data
- ✅ `PrismaService` creates/updates user in database
- ✅ `EmailService` sends password email
- ✅ JWT tokens generated
- ✅ Redirects with tokens in URL

---

## 🎯 Detailed Endpoint Flow

### **Route: GET /auth/discord**

```
Browser Request:
GET http://localhost:6545/auth/discord

↓ Passport Intercept ↓

DiscordStrategy.constructor()
├─ Read: DISCORD_CLIENT_ID
├─ Read: DISCORD_CLIENT_SECRET
├─ Read: DISCORD_CALLBACK_URL
└─ Initialize OAuth2 strategy

↓ No validate() needed for auth initiation ↓

Response:
302 Redirect → https://discord.com/oauth2/authorize?...
```

---

### **Route: GET /auth/discord/callback**

```
Browser Request:
GET http://localhost:6545/auth/discord/callback?code=abc123&state=xyz789

↓ Passport Intercept ↓

DiscordStrategy.validate()
├─ Exchange code for access token
│  └─ POST https://discord.com/api/v10/oauth2/token
│     ├─ Send: client_id, client_secret, code, redirect_uri
│     └─ Receive: access_token, token_type, expires_in
├─ Fetch Discord user profile
│  └─ GET https://discord.com/api/v10/users/@me
│     ├─ Header: Authorization: Bearer [access_token]
│     └─ Receive: {id, username, email, avatar, ...}
└─ Extract user data:
   ├─ discordId: profile.id
   ├─ username: profile.username
   ├─ email: profile.email
   ├─ avatar: CDN URL
   └─ Return to controller

↓ Controller Receives req.user ↓

AuthService.discordAuthCallback(req.user)
├─ Query Database:
│  └─ SELECT * FROM "User"
│     WHERE discord = ? OR email = ?
├─ If NEW user:
│  ├─ generateStrongPassword() [16 chars, mixed entropy]
│  ├─ hashText() [bcrypt hash]
│  ├─ Database INSERT:
│  │  └─ INSERT INTO "User" (id, email, discord, password, ...)
│  └─ EmailService.sendGoogleAuthPassword()
│     └─ SMTP Connect → Compose → Send
├─ If EXISTING user (no discord):
│  └─ Database UPDATE:
│     └─ UPDATE "User" SET discord = ?, emailVerified = true
└─ AuthService.generateTokens()
   ├─ JwtService.sign() for access token
   └─ JwtService.sign() for refresh token

↓ Response ↓

Set Cookies:
├─ Set-Cookie: accessToken=eyJhbGc... (httpOnly, Secure)
├─ Set-Cookie: refreshToken=eyJhbGc... (httpOnly, Secure)
└─ 302 Redirect:
   http://localhost:3000/?
   access_token=eyJhbGc...&
   refresh_token=eyJhbGc...&
   user={...}
```

---

## 📝 Complete Backend Endpoint Map

| Endpoint                 | Method | Guard                  | Purpose        | Calls                                 |
| ------------------------ | ------ | ---------------------- | -------------- | ------------------------------------- |
| `/auth/discord`          | GET    | `AuthGuard('discord')` | Start OAuth    | DiscordStrategy                       |
| `/auth/discord/callback` | GET    | `AuthGuard('discord')` | OAuth callback | DiscordStrategy + discordAuthCallback |

---

## 🔍 Supporting Services Called

### **1. DiscordStrategy** (`src/lib/strategy/discord.strategy.ts`)

- **Method:** `validate(accessToken, refreshToken, profile, done)`
- **Purpose:** Extract Discord user data
- **Returns:** `{ discordId, username, email, avatar, provider }`

### **2. AuthService.discordAuthCallback** (`src/auth/auth.service.ts`)

- **Method:** `async discordAuthCallback(discordUserData)`
- **Purpose:** Create/link user, generate tokens
- **Database Queries:**
  - Check existence (findFirst)
  - Create user (create)
  - Update user (update)
- **Returns:** `{ success, access_token, refresh_token, user }`

### **3. EmailService** (`src/email/email.service.ts`)

- **Method:** `sendGoogleAuthPassword(email, password, username, name)`
- **Purpose:** Send password to new user
- **Connection:** SMTP (Gmail)

### **4. JwtService** (NestJS built-in)

- **Method:** `sign(payload, options)`
- **Purpose:** Generate JWT tokens
- **Uses:** `JWT_SECRET` from env

### **5. PrismaService** (`src/lib/prisma/prisma.service.ts`)

- **Queries:**
  - `user.findFirst()` - Check existence
  - `user.create()` - Create new user
  - `user.update()` - Link Discord ID

---

## 📊 Database Interactions

### **Query 1: Check User Existence**

```sql
SELECT * FROM "User"
WHERE discord = '123456789'
   OR email = 'user@discord.com'
LIMIT 1;
```

### **Query 2: Create New User (First-time)**

```sql
INSERT INTO "User" (
  id, email, name, username, password,
  discord, avatar, emailVerified, auth_provider
) VALUES (
  'user_1234567890_abc123xyz',
  'user@discord.com',
  'discord_username',
  'unique_username_123',
  '$2a$10$hashed_password_here...',
  '123456789',
  'https://cdn.discordapp.com/avatars/123456789/avatar_hash.png',
  true,
  'discord'
);
```

### **Query 3: Update User (Linking)**

```sql
UPDATE "User"
SET discord = '123456789', emailVerified = true
WHERE id = 'existing_user_id';
```

---

## 🔑 Environment Variables Used

**For Discord OAuth:**

```
DISCORD_CLIENT_ID=1464773208359305317
DISCORD_CLIENT_SECRET=RrdtfNUQtUDO8Q86NJZzF4gxngmXcQa7
DISCORD_CALLBACK_URL=http://localhost:6545/auth/discord/callback
```

**For JWT:**

```
JWT_SECRET=your-secret-key-here
```

**For Email:**

```
EMAIL_FROM=your-email@gmail.com
EMAIL_PASSWORD=your-app-specific-password
SMTP_HOST=smtp.gmail.com
SMTP_PORT=587
```

**For Frontend:**

```
FRONTEND_URL=http://localhost:3000
```

---

## ✅ Testing Checklist - কি কি check করবেন

- [ ] Browser navigates to Discord login
- [ ] Discord shows authorization dialog
- [ ] Browser redirects back to localhost:6545
- [ ] Server logs: "✅ New user created via Discord: email@domain.com"
- [ ] Server logs: "✅ Password email sent to: email@domain.com"
- [ ] User data displays on frontend
- [ ] Tokens visible in textarea
- [ ] Database has new user with discord field
- [ ] Email received with password
- [ ] Second Discord login doesn't create duplicate
- [ ] JWT tokens valid on jwt.io

---

**সর্বমোট Hits (কতবার backend call হয়):**

- 2 HTTP endpoints (discord, discord/callback)
- Multiple internal service calls
- 3+ Database queries
- 1 Email sent
- 2 JWT tokens generated

**Status: ✅ READY TO TEST**
