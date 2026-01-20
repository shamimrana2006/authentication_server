# 🔐 NestJS Authentication with Email OTP Verification

A production-ready authentication system built with **NestJS**, **Prisma**, **PostgreSQL**, and **Email OTP verification**.

## ✨ Features

✅ **18 Complete Authentication Endpoints**

- Registration & Login with JWT
- Email verification with OTP
- Password reset with OTP
- Username management
- User profile management
- Multi-device session tracking
- Logout from all devices

✅ **Security Features**

- Email verification required before login
- 6-digit OTP with 10-minute expiry
- Two-step password reset verification
- Password hashing with bcrypt
- JWT access & refresh tokens
- Multi-device session management

✅ **Email Notifications**

- Email verification OTPs
- Password reset OTPs
- Username reminders
- Password change notifications

## 📚 Documentation

- 📖 **[SETUP_GUIDE.md](SETUP_GUIDE.md)** - Quick setup and configuration
- 📖 **[AUTH_DOCUMENTATION.md](AUTH_DOCUMENTATION.md)** - Complete API documentation
- 📖 **[FEATURES_SUMMARY.md](FEATURES_SUMMARY.md)** - All implemented features
- 📖 **[test-auth.http](test-auth.http)** - REST Client test suite

## 🚀 Quick Start

### 1. Install Dependencies

```bash
pnpm install
```

### 2. Configure Environment

Copy `.env.example` to `.env` and update:

```env
DATABASE_URL="postgresql://user:password@localhost:5432/auth_db"
JWT_SECRET="your-secret-key"
MAIL_USER="your-email@gmail.com"
MAIL_PASSWORD="your-app-password"
```

### 3. Setup Database

```bash
pnpm mg  # Run migrations and generate Prisma client
```

### 4. Start Server

```bash
pnpm start:dev
```

Server: `http://localhost:3000`  
Swagger: `http://localhost:3000/api`

## 📋 API Endpoints

### Authentication (4 endpoints)

- `POST /auth/register` - Register new user
- `POST /auth/login` - Login
- `POST /auth/logout` - Logout current device
- `POST /auth/refresh-token` - Refresh token

### Email Verification (2 endpoints)

- `POST /auth/verify-email` - Verify email with OTP
- `POST /auth/resend-verification-otp` - Resend OTP

### Password Management (5 endpoints)

- `POST /auth/forgot-password` - Send reset OTP
- `POST /auth/verify-reset-otp` - Verify reset OTP
- `POST /auth/reset-password` - Reset password
- `POST /auth/resend-reset-otp` - Resend reset OTP
- `PUT /auth/change-password` - Change password

### Username Management (3 endpoints)

- `POST /auth/check-username` - Check availability
- `PUT /auth/update-username` - Update username
- `POST /auth/forgot-username` - Send username to email

### Profile & Security (4 endpoints)

- `GET /auth/me` - Get current user
- `PUT /auth/profile` - Update profile
- `GET /auth/sessions` - View active sessions
- `DELETE /auth/logout-all` - Logout all devices

## 🔄 Authentication Flow

### Registration → Verification → Login

```
1. POST /auth/register
   → User receives OTP via email

2. POST /auth/verify-email
   → Email is verified

3. POST /auth/login
   → Returns access_token & refresh_token

4. Use access_token for protected routes
```

### Password Reset

```
1. POST /auth/forgot-password
   → User receives reset OTP

2. POST /auth/verify-reset-otp
   → OTP is verified

3. POST /auth/reset-password
   → Password is reset, all sessions cleared
```

## 🧪 Testing

### Option 1: REST Client (VS Code)

1. Install REST Client extension
2. Open `test-auth.http`
3. Click "Send Request" on each endpoint

### Option 2: Swagger UI

Visit `http://localhost:3000/api`

### Option 3: curl

```bash
curl -X POST http://localhost:3000/auth/register \
  -H "Content-Type: application/json" \
  -d '{"name":"Test","email":"test@example.com","password":"Test123"}'
```

## 📦 Project Structure

```
src/
├── auth/               # Authentication module
│   ├── dto/           # Data transfer objects
│   ├── auth.controller.ts
│   ├── auth.service.ts
│   └── auth.module.ts
├── email/             # Email service
├── user/              # User module
├── lib/               # Shared libraries
│   ├── prisma/        # Database service
│   └── strategy/      # Passport strategies
└── common/            # Utilities

prisma/
├── schema/            # Database schemas
└── migrations/        # Database migrations
```

## 🛠️ Development Commands

```bash
pnpm start:dev      # Start dev server
pnpm build          # Build for production
pnpm mg             # Run migrations
pnpm studio         # Open Prisma Studio
pnpm reset          # Reset database
```

## 🔐 Security Best Practices

✅ Passwords hashed with bcrypt  
✅ OTPs expire after 10 minutes  
✅ Email verification required  
✅ Refresh tokens in database  
✅ Session tracking  
✅ All sessions cleared on password change

## 📄 License

MIT License

---

Built with ❤️ using [NestJS](https://nestjs.com/), [Prisma](https://www.prisma.io/), and PostgreSQL

````

## Compile and run the project

```bash
# development
$ pnpm run start

# watch mode
$ pnpm run start:dev

# production mode
$ pnpm run start:prod
````

## Run tests

```bash
# unit tests
$ pnpm run test

# e2e tests
$ pnpm run test:e2e

# test coverage
$ pnpm run test:cov
```

## Deployment

When you're ready to deploy your NestJS application to production, there are some key steps you can take to ensure it runs as efficiently as possible. Check out the [deployment documentation](https://docs.nestjs.com/deployment) for more information.

If you are looking for a cloud-based platform to deploy your NestJS application, check out [Mau](https://mau.nestjs.com), our official platform for deploying NestJS applications on AWS. Mau makes deployment straightforward and fast, requiring just a few simple steps:

```bash
$ pnpm install -g @nestjs/mau
$ mau deploy
```

With Mau, you can deploy your application in just a few clicks, allowing you to focus on building features rather than managing infrastructure.

## Resources

Check out a few resources that may come in handy when working with NestJS:

- Visit the [NestJS Documentation](https://docs.nestjs.com) to learn more about the framework.
- For questions and support, please visit our [Discord channel](https://discord.gg/G7Qnnhy).
- To dive deeper and get more hands-on experience, check out our official video [courses](https://courses.nestjs.com/).
- Deploy your application to AWS with the help of [NestJS Mau](https://mau.nestjs.com) in just a few clicks.
- Visualize your application graph and interact with the NestJS application in real-time using [NestJS Devtools](https://devtools.nestjs.com).
- Need help with your project (part-time to full-time)? Check out our official [enterprise support](https://enterprise.nestjs.com).
- To stay in the loop and get updates, follow us on [X](https://x.com/nestframework) and [LinkedIn](https://linkedin.com/company/nestjs).
- Looking for a job, or have a job to offer? Check out our official [Jobs board](https://jobs.nestjs.com).

## Support

Nest is an MIT-licensed open source project. It can grow thanks to the sponsors and support by the amazing backers. If you'd like to join them, please [read more here](https://docs.nestjs.com/support).

## Stay in touch

- Author - [Kamil Myśliwiec](https://twitter.com/kammysliwiec)
- Website - [https://nestjs.com](https://nestjs.com/)
- Twitter - [@nestframework](https://twitter.com/nestframework)

## License

Nest is [MIT licensed](https://github.com/nestjs/nest/blob/master/LICENSE).
