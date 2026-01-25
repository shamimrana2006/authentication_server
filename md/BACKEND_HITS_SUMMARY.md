# 🎯 Discord OAuth Testing - Backend Endpoints Reference

## সার্ভার Status

✅ **Server Running:** http://localhost:6545
✅ **Testing Page:** http://localhost:6545/auth/socialLogin.html
✅ **API Docs:** http://localhost:6545/api-docs

---

## 🔴 Discord Login করার সময় Backend এ কি Hit হয়

### **সরাসরি 2 টি HTTP Endpoints:**

```
1️⃣  GET /auth/discord
    └─ ব্যবহারকারী "Discord দিয়ে লগিন করুন" ক্লিক করে
    └─ এই endpoint এ যায়
    └─ Passport Discord Strategy activate হয়
    └─ Discord authorization page এ redirect হয়

2️⃣  GET /auth/discord/callback
    └─ Discord login করে অনুমোদন দেয়
    └─ এই callback endpoint এ ফিরে আসে
    └─ Authorization code পায়
    └─ User data fetch করে
    └─ Database এ create/update করে
    └─ Tokens generate করে
    └─ Frontend এ redirect করে
```

---

## 📊 পুরো Flow এ কি কি হয়

### **Step 1: User clicks Discord button**

```
Frontend Button → GET http://localhost:6545/auth/discord
```

### **Step 2: Backend - DiscordStrategy initialized**

```
AuthGuard('discord') activates
    ↓
DiscordStrategy constructor runs
    ├─ Read from .env: DISCORD_CLIENT_ID
    ├─ Read from .env: DISCORD_CLIENT_SECRET
    ├─ Read from .env: DISCORD_CALLBACK_URL
    └─ Prepare OAuth URL
```

### **Step 3: Browser redirects to Discord**

```
Response: 302 Redirect to Discord OAuth Page
https://discord.com/oauth2/authorize?client_id=...&scope=identify%20email&redirect_uri=...
```

### **Step 4: User logs in on Discord & authorizes**

```
User enters Discord credentials
User clicks "Authorize"
```

### **Step 5: Discord redirects back to backend**

```
Discord → GET /auth/discord/callback?code=abc123&state=xyz
```

### **Step 6: Passport intercepts callback**

```
DiscordStrategy.validate() is called
    ├─ Exchange code for access_token
    │  └─ POST to Discord API
    │     └─ Receive: access_token, token_type
    ├─ Fetch Discord profile
    │  └─ GET https://discord.com/api/users/@me
    │     └─ Receive: {id, username, email, avatar}
    └─ Extract data into object:
       {
         discordId: "123456789",
         username: "discord_username",
         email: "user@discord.com",
         avatar: "https://cdn.discord...",
         provider: "discord"
       }
```

### **Step 7: discordAuthCallback processes user**

```
AuthService.discordAuthCallback(discordUserData)
    ├─ Query Database:
    │  └─ SELECT * FROM User WHERE discord=? OR email=?
    │
    ├─ If NEW user (not found):
    │  ├─ Generate strong password (16 chars)
    │  ├─ Hash password with bcrypt
    │  ├─ Insert new user in database:
    │  │  INSERT INTO User (
    │  │    id, email, username, password,
    │  │    discord, avatar, emailVerified
    │  │  )
    │  └─ Send email with password
    │
    ├─ If EXISTING user (found without discord):
    │  └─ Link Discord ID:
    │     UPDATE User SET discord=?, emailVerified=true
    │
    └─ Generate JWT tokens:
       ├─ Access token (1 hour expiry)
       └─ Refresh token (longer expiry)
```

### **Step 8: Response with tokens**

```
Response:
├─ Set-Cookie: accessToken=eyJhbGc... (httpOnly)
├─ Set-Cookie: refreshToken=eyJhbGc... (httpOnly)
└─ Redirect: http://localhost:3000/?
   access_token=eyJhbGc...&
   refresh_token=eyJhbGc...&
   user={...}
```

### **Step 9: Frontend receives & processes**

```
Frontend extracts from query params
    ├─ accessToken
    ├─ refreshToken
    └─ user data

Display user info
Store in localStorage
Show in textarea
```

---

## 🔍 Backend Service Calls চলার সময়

```
AuthController.discordCallback()
    ├─ DiscordStrategy.validate()
    │  └─ Calls Passport OAuth flow
    │
    ├─ AuthService.discordAuthCallback()
    │  ├─ Calls PrismaService.user.findFirst()
    │  ├─ Calls PrismaService.user.create() or .update()
    │  ├─ Calls EmailService.sendGoogleAuthPassword()
    │  ├─ Calls generateStrongPassword()
    │  ├─ Calls hashText()
    │  └─ Calls AuthService.generateTokens()
    │
    └─ Returns response with cookies
```

---

## 📋 সব HTTP Endpoints List

| #   | Endpoint                 | Method | Purpose                | Status |
| --- | ------------------------ | ------ | ---------------------- | ------ |
| 1   | `/auth/discord`          | GET    | Discord login শুরু করে | ✅     |
| 2   | `/auth/discord/callback` | GET    | Discord থেকে callback  | ✅     |
| 3   | `/auth/register`         | POST   | Regular registration   | ✅     |
| 4   | `/auth/login`            | POST   | Regular login          | ✅     |
| 5   | `/auth/google-login`     | POST   | Google Firebase login  | ✅     |
| 6   | `/auth/logout`           | DELETE | Logout                 | ✅     |
| 7   | `/auth/refresh-token`    | POST   | Refresh JWT token      | ✅     |
| 8   | `/auth/me`               | GET    | Current user info      | ✅     |

---

## 🎯 Test এর সময় Backend Logs দেখুন

```
Terminal output should show:

[Nest] 7476 - ... LOG [RouterExplorer] Mapped {/auth/discord, GET}
[Nest] 7476 - ... LOG [RouterExplorer] Mapped {/auth/discord/callback, GET}

✅ Firebase initialized for Google Auth

data base connected

API docs available at http://localhost:6545/api-docs
```

**যখন Discord login করবেন তখন লাইভ logs:**

```
✅ New user created via Discord: user@discord.com
✅ Password email sent to: user@discord.com
```

---

## 🧪 Test করার Command

### **1. Open Login Page**

```
Browser: http://localhost:6545/auth/socialLogin.html
```

### **2. Click Discord Button**

```
Click: "Discord দিয়ে লগিন করুন"
```

### **3. Complete Discord Auth**

```
Discord Login → Authorize → Done
```

### **4. Check Results**

**Browser Console:**

```javascript
// Press F12 → Console
✅ Firebase ready! Click a button to sign in.
```

**Browser localStorage:**

```
F12 → Application → LocalStorage
✅ accessToken
✅ refreshToken
✅ user
```

**Server Terminal:**

```
✅ New user created via Discord: email@domain.com
✅ Password email sent to: email@domain.com
```

**Email Inbox:**

```
✅ Subject: Your Account Password
✅ Contains: Generated password
✅ Contains: Username
```

**Database (Prisma Studio):**

```bash
pnpm exec prisma studio

# Look in Users table:
✅ discord field populated with Discord user ID
✅ emailVerified = true
✅ password = hashed value
```

---

## 📊 Database Queries চলার সময়

```sql
-- Query 1: Check if user exists
SELECT * FROM "User" WHERE discord = '123456789' OR email = 'user@discord.com' LIMIT 1;

-- Query 2: Create new user (if not found)
INSERT INTO "User" (id, email, name, username, password, discord, avatar, emailVerified, auth_provider, createdAt, updatedAt)
VALUES ('user_123_abc', 'user@discord.com', 'discord_user', 'discord_user_1', '$2a$10$hash...', '123456789', 'avatar_url', true, 'discord', now(), now());

-- Query 3: OR Update existing user (if found without discord)
UPDATE "User" SET discord = '123456789', emailVerified = true WHERE id = 'existing_id';
```

---

## 🔐 Security চেক করুন

✅ **Password Security:**

- Auto-generated 16 char password
- Mixed case, numbers, symbols
- Bcrypt hashed (not plain text)
- Sent via email only

✅ **Token Security:**

- JWT signed with secret
- HTTPOnly cookies
- Access token: 1 hour expiry
- Refresh token: longer expiry

✅ **Email Verification:**

- Discord automatically verifies
- emailVerified = true

---

## 📝 সবকিছুর সারসংক্ষেপ

| Item                    | Details                       |
| ----------------------- | ----------------------------- |
| **Total Endpoints Hit** | 2 (discord, discord/callback) |
| **Database Queries**    | 1-3 (check, create/update)    |
| **External APIs**       | Discord OAuth API             |
| **Email Sent**          | 1 per new user                |
| **Tokens Generated**    | 2 (access + refresh)          |
| **Services Called**     | 7+ internal services          |
| **File Served**         | 1 (socialLogin.html)          |

---

## ✅ সাফল্যের লক্ষণ

- [x] User info displays on page
- [x] Tokens visible in textarea
- [x] Email received
- [x] Database has new user
- [x] Backend logs show success
- [x] Logout works
- [x] Second login doesn't duplicate

---

## 📚 বিস্তারিত Documentation

- ✅ [BACKEND_ENDPOINTS_FLOW.md](BACKEND_ENDPOINTS_FLOW.md) - সম্পূর্ণ flow diagram
- ✅ [DISCORD_AUTH_IMPLEMENTATION.md](DISCORD_AUTH_IMPLEMENTATION.md) - Implementation details
- ✅ [DISCORD_TESTING_GUIDE.md](DISCORD_TESTING_GUIDE.md) - Testing guide

---

**Status: ✅ READY TO TEST NOW**

**Start:** http://localhost:6545/auth/socialLogin.html
