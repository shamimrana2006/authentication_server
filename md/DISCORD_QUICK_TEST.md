# Discord OAuth Testing - Quick Commands

## 🚀 Server Status

✅ Server running on: **http://localhost:6545**
✅ API Docs: http://localhost:6545/api-docs
✅ Discord Routes Mapped:

- GET /auth/discord (initiates OAuth)
- GET /auth/discord/callback (OAuth callback)

---

## 📱 Test Discord Login (Browser)

**1. Open this URL in your browser:**

```
http://localhost:6545/auth/socialLogin.html
```

**2. Click "Sign in with Discord" button (Bengali: "Discord দিয়ে লগিন করুন")**

**3. Complete Discord authorization**

**4. Check results:**

- ✅ User info displays on page
- ✅ JWT tokens shown in textarea
- ✅ Check email for password notification
- ✅ Check database for new user

---

## 🔍 Verify Results

### Check Browser Console (F12)

```javascript
// Should show:
✅ Firebase ready! Click a button to sign in.
✅ Backend URL: http://localhost:6545/auth/firebase-login
```

### Check Browser LocalStorage (F12 → Application)

```
✅ accessToken: eyJhbGc...
✅ refreshToken: eyJhbGc...
✅ user: {"id":"user_...", "email":"..."}
```

### Check Server Logs

```
✅ New user created via Discord: [email]
✅ Password email sent to: [email]
```

### Check Database

```bash
# Open Prisma Studio
pnpm exec prisma studio

# Look in Users table for:
- discord field = [discord user id]
- emailVerified = true
```

### Check Email

- Inbox for: "Your Account Password"
- Contains: auto-generated password
- Contains: username and security info

---

## 🐛 Troubleshooting

**If Discord button doesn't redirect:**

- ❌ Check Discord CLIENT_ID in .env
- ❌ Check DISCORD_CLIENT_SECRET in .env
- ❌ Verify DISCORD_CALLBACK_URL in .env

**If redirect fails:**

- Check server logs for: `❌ Discord auth callback error`
- Check browser console for errors (F12)

**If email not received:**

- Check server logs for: `✅ Password email sent`
- Verify EMAIL_FROM and EMAIL_PASSWORD in .env

**If no user created:**

- Check database connection
- Check server logs for errors
- Verify Prisma migration ran

---

## 📊 Full Test Checklist

```
[ ] Server running on port 6545
[ ] socialLogin.html loads (http://localhost:6545/auth/socialLogin.html)
[ ] Discord button visible with icon
[ ] Clicking Discord button redirects to Discord login
[ ] Discord shows authorization dialog
[ ] After auth, redirects back to socialLogin.html
[ ] User info displays on page (email, name, username)
[ ] JWT tokens visible in textarea
[ ] Copy button works (copies token to clipboard)
[ ] localStorage has accessToken, refreshToken, user
[ ] Database has new user with discord field
[ ] Email received with password
[ ] Logout button clears all data
[ ] Second Discord login doesn't create duplicate user
```

---

## 🔑 Account Used for Testing

```
Discord OAuth Credentials (Already configured):
CLIENT_ID: 1464773208359305317
CLIENT_SECRET: RrdtfNUQtUDO8Q86NJZzF4gxngmXcQa7
CALLBACK_URL: http://localhost:6545/auth/discord/callback
```

---

## 📝 Success Indicators

**Frontend:** User info displays on socialLogin.html
**Backend:** Logs show "✅ New user created via Discord"
**Email:** Password email arrives within 2 seconds
**Database:** User created with `discord` field populated
**Tokens:** JWT tokens shown and stored in localStorage

---

**Status: ✅ READY TO TEST**
**Start with:** http://localhost:6545/auth/socialLogin.html
