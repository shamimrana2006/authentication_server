# Discord OAuth Testing Guide 🧪

## ⚡ Quick Start Test (5 minutes)

### Step 1: Start the Server

```bash
cd "c:\Users\Shamim Rana\workspace\deployed project\authentication_server"
pnpm start
```

**Expected Output:**

```
[Nest] 12345  - 01/25/2026, 6:30 AM     LOG [NestFactory] Starting Nest application...
[Nest] 12345  - 01/25/2026, 6:30 AM     LOG [InstanceLoader] DatabaseModule dependencies initialized
[Nest] 12345  - 01/25/2026, 6:30 AM     LOG [InstanceLoader] AuthModule dependencies initialized
[Nest] 12345  - 01/25/2026, 6:30 AM     LOG [NestFactory] Nest application successfully started
```

✅ Server running on `http://localhost:6545`

---

### Step 2: Open Login Page (Browser)

Navigate to:

```
http://localhost:6545/auth/socialLogin.html
```

**What You'll See:**

- Firebase Authentication Test page
- 3 login buttons: Google, Discord, Apple
- Backend URL configuration input

---

### Step 3: Test Discord Login

**Click:** "Sign in with Discord" button

**Flow:**

1. ↪️ Redirects to Discord login page
2. 📱 Login with your Discord account
3. 🔐 Discord asks for authorization (identify, email)
4. ✅ Redirects back to socialLogin.html
5. 👤 User info displays on page

**Expected Result:**

```
✅ User Info Shows:
- Email: [your discord email]
- Name: [your discord username]
- User ID: user_1234567890_abc123xyz
- Username: [auto-generated unique username]
- Provider: discord
- JWT Token: eyJhbGc...
```

---

## 🔍 Step-by-Step Testing

### Test 1: New User Registration

**Scenario:** First-time Discord login

**Steps:**

1. Open `http://localhost:6545/auth/socialLogin.html`
2. Click "Discord দিয়ে লগিন করুন"
3. Complete Discord authorization
4. Check user info displays

**Verify in Database:**

```bash
# Check PostgreSQL database
# Look for new user with:
- discord field = [discord user id]
- emailVerified = true
- password = [hashed auto-generated password]
- email = [discord email]
```

**Verify Email Sent:**

```bash
# Check email inbox for:
- Subject: "Your Account Password"
- Contains: generated password
- Contains: username
- Contains: security warnings
```

**Expected Tokens:**

- ✅ access_token (JWT)
- ✅ refresh_token (JWT)

---

### Test 2: Existing User Linking

**Scenario:** User already has account via Google, now logs in with Discord

**Steps:**

1. First, register via Google OAuth
2. Then, try Discord login with same email
3. Should link Discord ID to existing account

**Database State:**

- User should have BOTH `google` AND `discord` fields populated
- No new user created
- Single email address

---

### Test 3: Token Validation

**Test JWT Tokens Received:**

```bash
# Copy the JWT token from the page
# Paste at: https://jwt.io/

# You should see payload:
{
  "sub": "user_1234567890_abc123xyz",
  "email": "your@email.com",
  "username": "your_username",
  "iat": 1234567890,
  "exp": 1234571490
}
```

---

### Test 4: Local Storage Verification

**Open Browser DevTools** (F12)

**Check Application → Local Storage → http://localhost:6545**

```
✅ accessToken: eyJhbGc...
✅ refreshToken: eyJhbGc...
✅ user: {"id":"user_...", "email":"..."}
```

---

### Test 5: Cookie Verification

**Open Browser DevTools** (F12)

**Check Application → Cookies → http://localhost:6545**

```
✅ accessToken: eyJhbGc...
✅ refreshToken: eyJhbGc...
```

---

## 🔧 Advanced Testing (Using HTTP Client)

### Test with VS Code REST Client

Create file: `test-discord.http`

```http
### Test Discord Login Endpoint (Initiates OAuth)
GET http://localhost:6545/auth/discord
Authorization: Bearer [access_token_here]

### Test Discord Callback (Manual - Not directly testable, needs OAuth flow)
GET http://localhost:6545/auth/discord/callback?code=DISCORD_CODE&state=STATE

```

---

## 🐛 Troubleshooting Tests

### Issue 1: "Discord দিয়ে লগিন করুন button not visible"

**Fix:**

```bash
# Clear browser cache
# Press: Ctrl + Shift + Delete
# Select: All time
# Clear all

# Then reload: http://localhost:6545/auth/socialLogin.html
```

---

### Issue 2: "Redirect to Discord fails"

**Check:**

```javascript
// In browser console (F12 → Console)
// Should show:
✅ Backend URL: http://localhost:6545/auth/firebase-login
✅ Firebase ready! Click a button to sign in.
```

**If error, check:**

- [ ] Discord CLIENT_ID correct in `.env`
- [ ] Discord CLIENT_SECRET correct in `.env`
- [ ] DISCORD_CALLBACK_URL = `http://localhost:6545/auth/discord/callback`
- [ ] Server running on port 6545

---

### Issue 3: "After Discord auth, blank page or redirect error"

**Check Server Logs:**

```bash
# Look for in terminal:
✅ New user created via Discord: your@email.com
✅ Password email sent to: your@email.com

# Or error:
❌ Discord auth callback error: [error message]
```

**Common Causes:**

- Discord OAuth app not authorized for redirect URL
- Email service not configured
- Database connection issue

---

### Issue 4: "Email not received"

**Check Server:**

```bash
# Look in terminal for:
✅ Password email sent to: [email]

# Or:
⚠️ Failed to send password email: [error]
```

**Verify Email Configuration in `.env`:**

```env
EMAIL_FROM=your-email@gmail.com
EMAIL_PASSWORD=your-app-specific-password
SMTP_HOST=smtp.gmail.com
SMTP_PORT=587
```

---

## 📊 Manual API Testing with cURL

### Test OAuth Initiation

```bash
curl -v http://localhost:6545/auth/discord
```

**Expected Response:** 302 redirect to Discord

---

### Test User Creation via Prisma Studio

```bash
# Open Prisma Studio (visual DB browser)
pnpm exec prisma studio

# Navigate to Users table
# Look for new user with:
- discord field populated
- emailVerified = true
```

---

## ✅ Complete Test Checklist

- [ ] **Server starts** without errors
- [ ] **socialLogin.html loads** properly
- [ ] **Discord button visible** with correct styling
- [ ] **Clicking Discord button** redirects to Discord login
- [ ] **Discord login works** with your Discord account
- [ ] **Redirects back** to socialLogin.html
- [ ] **User info displays** on page
- [ ] **Tokens visible** in textarea
- [ ] **localStorage** has accessToken, refreshToken, user
- [ ] **Cookies set** with tokens
- [ ] **Database user created** with discord field
- [ ] **Email received** with password
- [ ] **JWT tokens valid** (check on jwt.io)
- [ ] **Logout works** (clears tokens, shows login buttons)
- [ ] **Second login** doesn't create duplicate user
- [ ] **Different Discord account** creates new user separately

---

## 🎯 Expected Test Results

### For NEW Discord User:

**1. Frontend:**

```
✅ Sign in with Discord button redirects to Discord
✅ User info displays: name, email, username
✅ JWT tokens shown in textarea
✅ Copy button works
```

**2. Backend:**

```
✅ New user record created in database
✅ discord field = <discord_user_id>
✅ emailVerified = true
✅ password = hashed (auto-generated)
```

**3. Email:**

```
✅ Email received within 2 seconds
✅ Contains generated password
✅ Contains username
✅ Contains security warnings
```

**4. Database:**

```
SELECT * FROM "User" WHERE discord IS NOT NULL;
-- Should show your new user with all fields populated
```

---

## 🚀 Test Discord Credentials

Your Discord OAuth App Details:

```
CLIENT_ID: 1464773208359305317
CLIENT_SECRET: RrdtfNUQtUDO8Q86NJZzF4gxngmXcQa7
CALLBACK_URL: http://localhost:6545/auth/discord/callback
```

✅ Already configured in `.env`

---

## 📝 Recording Test Results

**Create file:** `DISCORD_TEST_RESULTS.txt`

```
Test Date: 2026-01-25
Tester: [Your Name]

=== NEW USER TEST ===
✅ Discord OAuth redirect works
✅ User data received correctly
✅ User created in database
✅ Email sent with password
✅ JWT tokens generated

=== EXISTING USER TEST ===
✅ Second login doesn't create duplicate
✅ Discord ID linked to account
✅ Login successful without new password email

=== TOKEN TEST ===
✅ JWT access token valid
✅ JWT refresh token valid
✅ Tokens stored in localStorage
✅ Tokens stored in cookies

=== EDGE CASES ===
✅ Logout clears all data
✅ Multiple Discord accounts separate
✅ Email verification auto-handled

Status: ✅ ALL TESTS PASSED
```

---

## 🆘 Get Help

If test fails:

1. **Check Server Logs:**

   ```bash
   # Look for error messages in terminal
   # Should show: ✅ New user created via Discord
   ```

2. **Check Browser Console:**

   ```
   F12 → Console → Look for errors
   ```

3. **Check Database:**

   ```bash
   pnpm exec prisma studio
   # Verify user created with discord field
   ```

4. **Check Email:**
   - Login to email account
   - Check spam folder
   - Check sent emails in test account

5. **Enable Debug Logs:**
   ```bash
   # In auth.service.ts, logs are already enabled
   # Look for: ✅ New user created via Discord
   # Look for: ✅ Password email sent to
   ```

---

**Status: ✅ READY TO TEST**

Start with Quick Start Test, then run complete checklist!
