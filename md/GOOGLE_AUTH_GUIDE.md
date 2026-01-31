# Google Login/Register Implementation Guide

## Overview

This guide explains how to implement Google Login/Register on your frontend using Firebase and your NestJS authentication server.

## Backend Endpoint

**Endpoint:** `POST /auth/google-login`

**Request Body:**

```json
{
  "token": "firebase-id-token-from-google-sign-in"
}
```

**Response (Success):**

```json
{
  "success": true,
  "message": "Login successful",
  "access_token": "jwt-access-token",
  "refresh_token": "jwt-refresh-token",
  "user": {
    "id": "user-id",
    "email": "user@gmail.com",
    "name": "User Name",
    "avatar": "https://...",
    "username": "username",
    "emailVerified": true,
    "role": "USER",
    "googleId": "google-uid",
    "createdAt": "2026-01-25T...",
    "updatedAt": "2026-01-25T..."
  }
}
```

## Frontend Implementation

### 1. Install Firebase SDK

```bash
npm install firebase
# or
pnpm add firebase
```

### 2. Initialize Firebase

Create a file `src/config/firebase.ts`:

```typescript
import { initializeApp } from 'firebase/app';
import { getAuth } from 'firebase/auth';

const firebaseConfig = {
  apiKey: process.env.REACT_APP_FIREBASE_API_KEY,
  authDomain: process.env.REACT_APP_FIREBASE_AUTH_DOMAIN,
  projectId: process.env.REACT_APP_FIREBASE_PROJECT_ID,
  storageBucket: process.env.REACT_APP_FIREBASE_STORAGE_BUCKET,
  messagingSenderId: process.env.REACT_APP_FIREBASE_MESSAGING_SENDER_ID,
  appId: process.env.REACT_APP_FIREBASE_APP_ID,
};

const app = initializeApp(firebaseConfig);
export const auth = getAuth(app);
```

### 3. Create Environment Variables

Create `.env.local` in your frontend root:

```env
REACT_APP_FIREBASE_API_KEY=your-api-key
REACT_APP_FIREBASE_AUTH_DOMAIN=jconnect-b6f89.firebaseapp.com
REACT_APP_FIREBASE_PROJECT_ID=jconnect-b6f89
REACT_APP_FIREBASE_STORAGE_BUCKET=jconnect-b6f89.appspot.com
REACT_APP_FIREBASE_MESSAGING_SENDER_ID=your-sender-id
REACT_APP_FIREBASE_APP_ID=your-app-id

REACT_APP_BACKEND_URL=http://localhost:6545
```

### 4. Create Google Login Hook

Create `src/hooks/useGoogleLogin.ts`:

```typescript
import { useState } from 'react';
import { GoogleAuthProvider, signInWithPopup } from 'firebase/auth';
import { auth } from '@/config/firebase';

interface GoogleUser {
  id: string;
  email: string;
  name: string;
  avatar: string;
  username: string;
  emailVerified: boolean;
  role: string;
  googleId: string;
}

interface AuthResponse {
  success: boolean;
  message: string;
  access_token: string;
  refresh_token: string;
  user: GoogleUser;
}

export function useGoogleLogin() {
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const handleGoogleSignIn = async () => {
    try {
      setLoading(true);
      setError(null);

      const provider = new GoogleAuthProvider();
      const result = await signInWithPopup(auth, provider);

      // Get Firebase ID Token
      const idToken = await result.user.getIdToken();

      // Send to backend
      const response = await fetch(
        `${process.env.REACT_APP_BACKEND_URL}/auth/google-login`,
        {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          credentials: 'include',
          body: JSON.stringify({ token: idToken }),
        },
      );

      if (!response.ok) {
        throw new Error('Backend authentication failed');
      }

      const data: AuthResponse = await response.json();

      // Store tokens in localStorage
      localStorage.setItem('access_token', data.access_token);
      localStorage.setItem('refresh_token', data.refresh_token);
      localStorage.setItem('user', JSON.stringify(data.user));

      return {
        success: true,
        message: data.message,
        user: data.user,
      };
    } catch (err) {
      const errorMessage =
        err instanceof Error ? err.message : 'Google login failed';
      setError(errorMessage);
      console.error('❌ Google login error:', err);
      return {
        success: false,
        message: errorMessage,
      };
    } finally {
      setLoading(false);
    }
  };

  return {
    handleGoogleSignIn,
    loading,
    error,
  };
}
```

### 5. Create Google Login Component

Create `src/components/GoogleLoginButton.tsx`:

```typescript
import React from 'react';
import { useGoogleLogin } from '@/hooks/useGoogleLogin';
import { useNavigate } from 'react-router-dom';

export function GoogleLoginButton() {
  const { handleGoogleSignIn, loading, error } = useGoogleLogin();
  const navigate = useNavigate();

  const handleClick = async () => {
    const result = await handleGoogleSignIn();
    if (result.success) {
      // Redirect to dashboard or home
      navigate('/dashboard');
    }
  };

  return (
    <div className="google-login">
      <button
        onClick={handleClick}
        disabled={loading}
        className="btn-google"
      >
        {loading ? '🔄 Signing in...' : '🔵 Sign in with Google'}
      </button>

      {error && <div className="error-message">{error}</div>}
    </div>
  );
}
```

### 6. Use in Login/Register Page

```typescript
import { GoogleLoginButton } from '@/components/GoogleLoginButton';

export function LoginPage() {
  return (
    <div className="login-container">
      <h1>Login</h1>

      {/* Traditional Login Form */}
      <form>{/* ... */}</form>

      <div className="divider">OR</div>

      {/* Google Login */}
      <GoogleLoginButton />
    </div>
  );
}
```

## Backend Flow

### What Happens When User Clicks "Sign in with Google"

1. **Frontend:**
   - User clicks "Sign in with Google"
   - Firebase popup opens
   - User authenticates with Google
   - Frontend receives Firebase ID Token

2. **Frontend → Backend:**
   - Sends ID Token to `/auth/google-login`

3. **Backend:**
   - Verifies ID Token with Firebase Admin SDK
   - Checks if user exists:
     - **If user exists:** Login user, generate JWT tokens
     - **If user doesn't exist:** Create new user, generate JWT tokens
   - Returns access_token, refresh_token, and user data

4. **Frontend:**
   - Stores tokens in localStorage/cookies
   - Redirects to dashboard

## User Auto-Registration Features

✅ **Auto-create user if doesn't exist**

- Name: From Google account
- Email: From Google account (auto-verified)
- Avatar: From Google account
- Username: Auto-generated unique username
- emailVerified: true (Google verifies email)

✅ **Link Google ID to existing users**

- If user exists with same email, links Google ID to that account

✅ **Same token system as regular auth**

- Uses same JWT tokens as password-based login
- Cookies are automatically set by backend

## Testing in Swagger

1. Open Swagger UI: `http://localhost:6545/api`
2. Find `/auth/google-login` endpoint
3. Click "Try it out"
4. Enter a valid Firebase ID Token:

```json
{
  "token": "eyJhbGciOiJSUzI1NiIsImtpZCI6IjEifQ..."
}
```

## Environment Variables Needed

**Backend (.env):**

```
FIREBASE_PROJECT_ID=jconnect-b6f89
FIREBASE_PRIVATE_KEY=-----BEGIN PRIVATE KEY-----\n...\n-----END PRIVATE KEY-----\n
FIREBASE_CLIENT_EMAIL=firebase-adminsdk-fbsvc@jconnect-b6f89.iam.gserviceaccount.com
```

**Frontend (.env.local):**

```
REACT_APP_FIREBASE_API_KEY=...
REACT_APP_FIREBASE_AUTH_DOMAIN=...
REACT_APP_FIREBASE_PROJECT_ID=...
REACT_APP_FIREBASE_STORAGE_BUCKET=...
REACT_APP_FIREBASE_MESSAGING_SENDER_ID=...
REACT_APP_FIREBASE_APP_ID=...
REACT_APP_BACKEND_URL=http://localhost:6545
```

## Database Schema

The `User` model in Prisma already supports Google OAuth:

```prisma
model User {
  id       String  @id @default(uuid())
  email    String  @unique
  username String? @unique
  password String? // null for OAuth users

  // OAuth Providers
  googleId String? @unique
  githubId String? @unique
  discord  String? @unique

  // ... other fields
}
```

No database migration needed - Google login is already supported!

## Error Handling

**Common Errors:**

| Error                              | Solution                                          |
| ---------------------------------- | ------------------------------------------------- |
| `Invalid or expired Google token`  | Firebase token expired, ask user to sign in again |
| `Firebase credentials are missing` | Check .env variables on backend                   |
| `Backend authentication failed`    | Check backend is running and accessible           |
| `Google login failed`              | Check Firebase config on frontend                 |

## Security Notes

✅ **Token verification:**

- Backend verifies ID Token with Firebase Admin SDK
- Prevents token forgery

✅ **Secure token storage:**

- Store in localStorage (for web)
- Or in secure cookies (httpOnly)
- Implement token refresh flow

✅ **CORS:**

- Make sure backend allows frontend origin in CORS config

## Next Steps

1. **Apple Sign-In:** Use same Firebase setup
2. **GitHub OAuth:** Implement similar flow
3. **Social Profile:** Store provider data in separate table
4. **Account Linking:** Allow users to link multiple providers

---

**Implementation Complete!** ✅

Your Google Login/Register system is now ready to use.
