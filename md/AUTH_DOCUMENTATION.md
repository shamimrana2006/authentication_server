# 🔐 NestJS Authentication with Email OTP Verification

A comprehensive authentication system built with NestJS, Prisma, PostgreSQL, and email OTP verification.

## ✨ Features

### 🔑 Registration & Login

- ✅ User registration with email verification
- ✅ Login with email or username
- ✅ JWT access & refresh tokens
- ✅ Session management with multi-device support
- ✅ Logout from current device or all devices

### 📧 Email Verification

- ✅ Email verification with 6-digit OTP
- ✅ OTP expires in 10 minutes
- ✅ Resend verification OTP
- ✅ Prevent login without email verification

### 🔒 Password Management

- ✅ Forgot password with OTP
- ✅ Verify reset OTP before password change
- ✅ Reset password with verified OTP
- ✅ Change password when logged in
- ✅ Resend password reset OTP
- ✅ Email notifications for password changes

### 👤 Username Management

- ✅ Check username availability
- ✅ Update username
- ✅ Send username reminder to email

### 🎨 User Profile

- ✅ Get current user information
- ✅ Update profile (name, avatar)

### 🛡️ Security

- ✅ View active sessions
- ✅ Logout from all devices
- ✅ Password hashing with bcrypt
- ✅ JWT-based authentication

## 🚀 Quick Start

### Prerequisites

- Node.js 18+
- PostgreSQL database
- Gmail account (or other SMTP service)

### Installation

1. **Clone and install dependencies**

```bash
pnpm install
```

2. **Configure environment variables**

Copy `.env.example` to `.env` and update:

```env
DATABASE_URL="postgresql://user:password@localhost:5432/mydb"
JWT_SECRET="your-secret-key-here"
MAIL_HOST="smtp.gmail.com"
MAIL_PORT=587
MAIL_USER="your-email@gmail.com"
MAIL_PASSWORD="your-app-password"
MAIL_FROM="your-email@gmail.com"
MAIL_FROM_NAME="Your App Name"
```

**For Gmail:**

1. Enable 2-factor authentication
2. Generate an App Password (not your regular password)
3. Use the App Password in `MAIL_PASSWORD`

4. **Run database migrations**

```bash
pnpm mg
# or
npx prisma migrate dev
npx prisma generate
```

4. **Start the server**

```bash
pnpm start:dev
```

The server will start at `http://localhost:3000`

## 📚 API Documentation

Access Swagger documentation at: `http://localhost:3000/api`

### API Endpoints

#### Registration & Login

| Method | Endpoint              | Description                |
| ------ | --------------------- | -------------------------- |
| POST   | `/auth/register`      | Register new user          |
| POST   | `/auth/login`         | Login with email/username  |
| POST   | `/auth/logout`        | Logout from current device |
| POST   | `/auth/refresh-token` | Refresh access token       |

#### Email Verification

| Method | Endpoint                        | Description             |
| ------ | ------------------------------- | ----------------------- |
| POST   | `/auth/verify-email`            | Verify email with OTP   |
| POST   | `/auth/resend-verification-otp` | Resend verification OTP |

#### Password Management

| Method | Endpoint                 | Description                 |
| ------ | ------------------------ | --------------------------- |
| POST   | `/auth/forgot-password`  | Send password reset OTP     |
| POST   | `/auth/verify-reset-otp` | Verify reset OTP            |
| POST   | `/auth/reset-password`   | Reset password              |
| POST   | `/auth/resend-reset-otp` | Resend reset OTP            |
| PUT    | `/auth/change-password`  | Change password (logged in) |

#### Username Management

| Method | Endpoint                | Description            |
| ------ | ----------------------- | ---------------------- |
| POST   | `/auth/check-username`  | Check availability     |
| PUT    | `/auth/update-username` | Update username        |
| POST   | `/auth/forgot-username` | Send username to email |

#### User Profile

| Method | Endpoint        | Description      |
| ------ | --------------- | ---------------- |
| GET    | `/auth/me`      | Get current user |
| PUT    | `/auth/profile` | Update profile   |

#### Security

| Method | Endpoint           | Description          |
| ------ | ------------------ | -------------------- |
| GET    | `/auth/sessions`   | View active sessions |
| DELETE | `/auth/logout-all` | Logout all devices   |

## 🔄 Authentication Flow

### 1. Registration Flow

```
1. POST /auth/register → User receives OTP via email
2. POST /auth/verify-email → User verifies email with OTP
3. POST /auth/login → User can now login
```

### 2. Login Flow

```
1. POST /auth/login → Returns access_token & refresh_token
2. Use access_token in Authorization header: Bearer <token>
3. When access_token expires, POST /auth/refresh-token
```

### 3. Password Reset Flow

```
1. POST /auth/forgot-password → User receives OTP via email
2. POST /auth/verify-reset-otp → Verify the OTP
3. POST /auth/reset-password → Set new password
```

## 📝 Example Requests

### Register User

```bash
POST /auth/register
{
  "name": "John Doe",
  "email": "john@example.com",
  "password": "Password123",
  "username": "johndoe"
}
```

### Verify Email

```bash
POST /auth/verify-email
{
  "email": "john@example.com",
  "otp": "123456"
}
```

### Login

```bash
POST /auth/login
{
  "emailOrUsername": "john@example.com",
  "password": "Password123"
}

Response:
{
  "access_token": "eyJhbG...",
  "refresh_token": "eyJhbG...",
  "user": { ... }
}
```

### Access Protected Routes

```bash
GET /auth/me
Authorization: Bearer eyJhbG...
```

## 🗄️ Database Schema

### User Model

- Email verification with OTP
- Password reset with OTP
- OAuth provider support (Google, GitHub, Discord)
- Role-based access control
- Profile information

### Session Model

- Multi-device session tracking
- Device info and IP address
- Automatic session expiry

### RefreshToken Model

- Secure refresh token storage
- Token expiry management

## 🔧 Configuration

### Email Providers

The system supports multiple email providers:

**Gmail**

```env
MAIL_HOST="smtp.gmail.com"
MAIL_PORT=587
```

**SendGrid**

```env
MAIL_HOST="smtp.sendgrid.net"
MAIL_PORT=587
```

**Mailgun**

```env
MAIL_HOST="smtp.mailgun.org"
MAIL_PORT=587
```

**AWS SES**

```env
MAIL_HOST="email-smtp.us-east-1.amazonaws.com"
MAIL_PORT=587
```

### JWT Configuration

Update JWT secret and expiry in `.env`:

```env
JWT_SECRET="your-very-secure-secret-key"
```

And in [auth.module.ts](src/auth/auth.module.ts):

```typescript
JwtModule.register({
  secret: process.env.JWT_SECRET,
  signOptions: { expiresIn: '1h' }, // Access token expiry
});
```

## 🧪 Testing

Use the included `test-auth.http` file with REST Client extension in VS Code:

1. Install REST Client extension
2. Open `test-auth.http`
3. Click "Send Request" above each endpoint

## 📦 Project Structure

```
src/
├── auth/                      # Authentication module
│   ├── dto/                   # Data transfer objects
│   ├── auth.controller.ts     # Auth endpoints
│   ├── auth.service.ts        # Auth business logic
│   └── auth.module.ts         # Auth module config
├── email/                     # Email service
│   ├── email.service.ts       # Email sending logic
│   └── email.module.ts        # Email module config
├── user/                      # User module
├── lib/                       # Shared libraries
│   ├── prisma/                # Prisma service
│   └── strategy/              # Passport strategies
└── common/                    # Common utilities

prisma/
├── schema/                    # Prisma schema files
│   ├── schema.prisma          # Main schema
│   └── user.prisma            # User models
└── migrations/                # Database migrations
```

## 🛠️ Development Commands

```bash
# Start development server
pnpm start:dev

# Run migrations and generate Prisma client
pnpm mg

# Open Prisma Studio (database GUI)
pnpm studio

# Reset database
pnpm reset

# Build for production
pnpm build

# Start production server
pnpm start:prod
```

## 🔐 Security Best Practices

1. ✅ Passwords are hashed with bcrypt
2. ✅ OTPs expire after 10 minutes
3. ✅ Email verification required before login
4. ✅ Refresh tokens stored in database
5. ✅ JWT tokens with proper expiry
6. ✅ Session tracking for multi-device support
7. ✅ Password reset requires OTP verification
8. ✅ All sessions cleared on password change

## 📄 License

This project is licensed under the MIT License.

## 🤝 Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## 📞 Support

For support, email your-email@example.com or open an issue in the repository.

---

Built with ❤️ using NestJS, Prisma, and PostgreSQL
