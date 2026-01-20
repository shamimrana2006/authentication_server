# 🚀 Quick Setup Guide

## Step 1: Configure Email Service

### For Gmail (Recommended for Testing)

1. **Enable 2-Factor Authentication** on your Gmail account
   - Go to: https://myaccount.google.com/security
   - Enable 2-Step Verification

2. **Generate App Password**
   - Go to: https://myaccount.google.com/apppasswords
   - Select "Mail" and "Other (Custom name)"
   - Name it "NestJS Auth App"
   - Copy the 16-character password

3. **Update .env file**

```env
MAIL_HOST="smtp.gmail.com"
MAIL_PORT=587
MAIL_USER="your-email@gmail.com"
MAIL_PASSWORD="xxxx xxxx xxxx xxxx"  # App password from step 2
MAIL_FROM="your-email@gmail.com"
MAIL_FROM_NAME="Your App Name"
```

## Step 2: Database Setup

1. **Ensure PostgreSQL is running**

```bash
# Check if running
docker ps

# If using Docker Compose
docker-compose up -d
```

2. **Update DATABASE_URL in .env**

```env
DATABASE_URL="postgresql://user:password@localhost:5432/auth_db"
```

3. **Run migrations**

```bash
pnpm mg
```

## Step 3: Start the Application

```bash
pnpm start:dev
```

Server will be available at: `http://localhost:3000`
Swagger docs at: `http://localhost:3000/api`

## Step 4: Test the Flow

### Option 1: Using REST Client (VS Code)

1. Install "REST Client" extension
2. Open `test-auth.http`
3. Follow the numbered requests in order

### Option 2: Using Swagger UI

1. Go to `http://localhost:3000/api`
2. Try the endpoints interactively

### Option 3: Using curl

```bash
# 1. Register
curl -X POST http://localhost:3000/auth/register \
  -H "Content-Type: application/json" \
  -d '{
    "name": "Test User",
    "email": "test@example.com",
    "password": "Test123456",
    "username": "testuser"
  }'

# 2. Check your email for OTP, then verify
curl -X POST http://localhost:3000/auth/verify-email \
  -H "Content-Type: application/json" \
  -d '{
    "email": "test@example.com",
    "otp": "123456"
  }'

# 3. Login
curl -X POST http://localhost:3000/auth/login \
  -H "Content-Type: application/json" \
  -d '{
    "emailOrUsername": "test@example.com",
    "password": "Test123456"
  }'
```

## Complete Authentication Flow Example

### 1️⃣ User Registration

```http
POST /auth/register
{
  "name": "John Doe",
  "email": "john@example.com",
  "password": "SecurePass123",
  "username": "johndoe"
}
```

✅ **Result**: User receives 6-digit OTP via email

### 2️⃣ Email Verification

```http
POST /auth/verify-email
{
  "email": "john@example.com",
  "otp": "123456"
}
```

✅ **Result**: Email is verified, user can now login

### 3️⃣ Login

```http
POST /auth/login
{
  "emailOrUsername": "john@example.com",
  "password": "SecurePass123"
}
```

✅ **Result**: Returns access_token and refresh_token

### 4️⃣ Access Protected Resource

```http
GET /auth/me
Authorization: Bearer <access_token>
```

✅ **Result**: Returns user profile

### 5️⃣ Password Reset (if needed)

```http
POST /auth/forgot-password
{
  "email": "john@example.com"
}

POST /auth/verify-reset-otp
{
  "email": "john@example.com",
  "otp": "654321"
}

POST /auth/reset-password
{
  "email": "john@example.com",
  "newPassword": "NewSecurePass123"
}
```

✅ **Result**: Password is reset, all sessions are cleared

## Troubleshooting

### Email not sending?

**Gmail blocks the login:**

- Make sure 2FA is enabled
- Use App Password, not regular password
- Check "Less secure app access" is OFF (use App Password instead)

**Still not working:**

```typescript
// Temporarily log emails to console (for development only)
// In email.service.ts
console.log('OTP:', otp);
```

### Database connection error?

```bash
# Check if PostgreSQL is running
docker ps

# Restart database
docker-compose down
docker-compose up -d

# Reset and migrate
pnpm reset
```

### OTP expired?

OTPs expire after 10 minutes. Request a new one:

```http
POST /auth/resend-verification-otp
{
  "email": "john@example.com"
}
```

## Environment Variables Checklist

Make sure your `.env` has all these:

```env
✅ DATABASE_URL
✅ JWT_SECRET
✅ MAIL_HOST
✅ MAIL_PORT
✅ MAIL_USER
✅ MAIL_PASSWORD
✅ MAIL_FROM
✅ MAIL_FROM_NAME
```

## Next Steps

1. ✅ Configure email service
2. ✅ Run migrations
3. ✅ Start server
4. ✅ Test registration flow
5. ✅ Verify email with OTP
6. ✅ Test login
7. ✅ Try protected routes

## Optional: Prisma Studio

View and edit your database visually:

```bash
pnpm studio
```

Opens at: `http://localhost:5555`

---

Need help? Check [AUTH_DOCUMENTATION.md](AUTH_DOCUMENTATION.md) for full API documentation.
