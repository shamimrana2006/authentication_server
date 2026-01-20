# 🚀 Production Deployment Checklist

## Pre-Deployment Checklist

### 1. Environment Configuration

- [ ] Update `JWT_SECRET` to a strong, unique value (min 32 characters)
- [ ] Configure production database URL
- [ ] Set up production email service (not Gmail personal account)
- [ ] Add all required environment variables
- [ ] Enable SSL/TLS for database connection
- [ ] Set `NODE_ENV=production`

### 2. Security Hardening

- [ ] Change default JWT expiry times if needed
- [ ] Enable CORS with specific origins (not `*`)
- [ ] Add rate limiting middleware
- [ ] Enable Helmet.js for security headers
- [ ] Set up HTTPS/SSL certificates
- [ ] Configure CSP (Content Security Policy)
- [ ] Add request size limits

### 3. Database

- [ ] Run production migrations
- [ ] Set up database backups
- [ ] Configure connection pooling
- [ ] Add database indexes if needed
- [ ] Test database failover

### 4. Email Service

- [ ] Switch to production email service (SendGrid, AWS SES, etc.)
- [ ] Verify email domain
- [ ] Set up SPF, DKIM, DMARC records
- [ ] Test email delivery
- [ ] Configure email rate limits

### 5. Code Review

- [ ] Remove all console.log statements
- [ ] Review and remove development-only code
- [ ] Check for hardcoded credentials
- [ ] Validate all environment variables are used
- [ ] Test all error handling paths

### 6. Testing

- [ ] Test all 18 endpoints in production-like environment
- [ ] Test OTP expiry scenarios
- [ ] Test concurrent user sessions
- [ ] Test email delivery under load
- [ ] Verify password reset flow
- [ ] Test token refresh mechanism

### 7. Monitoring & Logging

- [ ] Set up application monitoring (e.g., Sentry, DataDog)
- [ ] Configure structured logging
- [ ] Set up alerting for critical errors
- [ ] Monitor email delivery rates
- [ ] Track failed authentication attempts
- [ ] Set up uptime monitoring

### 8. Performance

- [ ] Enable production build optimizations
- [ ] Configure caching where appropriate
- [ ] Set up CDN for static assets
- [ ] Optimize database queries
- [ ] Test under expected load

---

## Environment Variables for Production

```env
# Application
NODE_ENV=production
PORT=3000

# Database
DATABASE_URL="postgresql://user:password@host:5432/dbname?schema=public&sslmode=require"

# JWT
JWT_SECRET="your-super-secure-secret-key-min-32-characters-here"
JWT_EXPIRES_IN="1h"
REFRESH_TOKEN_EXPIRES_IN="7d"

# Email Service (Example: SendGrid)
MAIL_HOST="smtp.sendgrid.net"
MAIL_PORT=587
MAIL_USER="apikey"
MAIL_PASSWORD="your-sendgrid-api-key"
MAIL_FROM="noreply@yourdomain.com"
MAIL_FROM_NAME="Your App Name"

# CORS
CORS_ORIGIN="https://yourdomain.com,https://app.yourdomain.com"

# Rate Limiting
RATE_LIMIT_TTL=60
RATE_LIMIT_MAX=100

# Session
SESSION_SECRET="another-super-secure-secret-key"
```

---

## Production Email Services Setup

### Option 1: SendGrid (Recommended)

1. Sign up at [sendgrid.com](https://sendgrid.com)
2. Verify your sender email/domain
3. Create an API key
4. Update `.env`:

```env
MAIL_HOST="smtp.sendgrid.net"
MAIL_PORT=587
MAIL_USER="apikey"
MAIL_PASSWORD="your-api-key"
```

### Option 2: AWS SES

1. Set up AWS SES in your region
2. Verify email/domain
3. Get SMTP credentials
4. Update `.env`:

```env
MAIL_HOST="email-smtp.us-east-1.amazonaws.com"
MAIL_PORT=587
MAIL_USER="your-smtp-username"
MAIL_PASSWORD="your-smtp-password"
```

### Option 3: Mailgun

1. Sign up at [mailgun.com](https://mailgun.com)
2. Add and verify your domain
3. Get SMTP credentials
4. Update `.env`:

```env
MAIL_HOST="smtp.mailgun.org"
MAIL_PORT=587
MAIL_USER="postmaster@your-domain.com"
MAIL_PASSWORD="your-mailgun-password"
```

---

## Deployment Steps

### Step 1: Build the Application

```bash
pnpm build
```

### Step 2: Test Production Build Locally

```bash
NODE_ENV=production pnpm start:prod
```

### Step 3: Deploy to Server

#### Option A: Docker

```dockerfile
FROM node:18-alpine
WORKDIR /app
COPY package*.json ./
RUN npm ci --only=production
COPY dist ./dist
COPY prisma ./prisma
RUN npx prisma generate
EXPOSE 3000
CMD ["node", "dist/main"]
```

```bash
docker build -t auth-app .
docker run -p 3000:3000 --env-file .env auth-app
```

#### Option B: PM2 (Node Process Manager)

```bash
npm install -g pm2
pm2 start dist/main.js --name auth-app
pm2 save
pm2 startup
```

#### Option C: Cloud Platforms

- **Vercel**: Connect GitHub repo, auto-deploys
- **Railway**: Connect GitHub, add PostgreSQL
- **Heroku**: Use Procfile: `web: node dist/main.js`
- **AWS ECS**: Use Docker image
- **Google Cloud Run**: Use Docker image

### Step 4: Run Migrations on Production DB

```bash
# SSH into server or use cloud shell
npx prisma migrate deploy
npx prisma generate
```

### Step 5: Verify Deployment

```bash
# Test health endpoint
curl https://your-domain.com/

# Test registration
curl -X POST https://your-domain.com/auth/register \
  -H "Content-Type: application/json" \
  -d '{"name":"Test","email":"test@example.com","password":"Test123456"}'
```

---

## Security Enhancements (Recommended)

### 1. Add Rate Limiting

```bash
pnpm add @nestjs/throttler
```

```typescript
// app.module.ts
import { ThrottlerModule } from '@nestjs/throttler';

@Module({
  imports: [
    ThrottlerModule.forRoot([{
      ttl: 60000,
      limit: 10,
    }]),
  ],
})
```

### 2. Add Helmet for Security Headers

```bash
pnpm add helmet
```

```typescript
// main.ts
import helmet from 'helmet';
app.use(helmet());
```

### 3. Enable CORS Properly

```typescript
// main.ts
app.enableCors({
  origin: process.env.CORS_ORIGIN?.split(',') || 'http://localhost:3000',
  credentials: true,
});
```

### 4. Add Request Validation Pipe

```typescript
// main.ts
app.useGlobalPipes(
  new ValidationPipe({
    whitelist: true,
    forbidNonWhitelisted: true,
    transform: true,
  }),
);
```

---

## Monitoring Setup

### 1. Add Sentry (Error Tracking)

```bash
pnpm add @sentry/node
```

```typescript
import * as Sentry from '@sentry/node';

Sentry.init({
  dsn: process.env.SENTRY_DSN,
  environment: process.env.NODE_ENV,
});
```

### 2. Add Winston Logger

```bash
pnpm add winston
```

### 3. Health Check Endpoint

```typescript
@Get('health')
healthCheck() {
  return {
    status: 'ok',
    timestamp: new Date().toISOString(),
    uptime: process.uptime(),
  };
}
```

---

## Post-Deployment Verification

### Test Checklist

- [ ] User registration works
- [ ] Email OTP is received
- [ ] Email verification works
- [ ] Login works after verification
- [ ] Refresh token works
- [ ] Password reset flow works
- [ ] All protected endpoints require authentication
- [ ] Logout works
- [ ] Session tracking works
- [ ] Profile update works

### Monitor First 24 Hours

- [ ] Check error logs
- [ ] Monitor email delivery rates
- [ ] Track authentication failures
- [ ] Monitor database performance
- [ ] Check API response times
- [ ] Verify no security issues

---

## Maintenance

### Regular Tasks

- [ ] Review logs weekly
- [ ] Update dependencies monthly
- [ ] Review security advisories
- [ ] Backup database regularly
- [ ] Monitor storage usage
- [ ] Review and optimize slow queries

### Emergency Contacts

- Database admin: ******\_\_\_******
- Email service support: ******\_\_\_******
- Hosting support: ******\_\_\_******

---

## Rollback Plan

If deployment fails:

1. **Database Rollback**

```bash
npx prisma migrate reset --skip-seed
npx prisma migrate deploy --to <previous-migration>
```

2. **Code Rollback**

```bash
git revert HEAD
git push
# Redeploy previous version
```

3. **Notifications**

- Notify users of maintenance
- Send status updates
- Document issue

---

**Status**: Ready for Production ✅
**Last Review**: January 14, 2026
