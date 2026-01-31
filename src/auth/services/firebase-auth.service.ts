import { Injectable, UnauthorizedException } from '@nestjs/common';
import * as admin from 'firebase-admin';
import { ConfigService } from '@nestjs/config';

@Injectable()
export class FirebaseAuthService {
  private firebaseApp: admin.app.App | null = null;
  private initializationAttempted = false;
  private credentialsAvailable = false;

  constructor(private configService: ConfigService) {
    // Check credentials availability without initializing
    this.checkCredentialsAvailable();
  }

  private checkCredentialsAvailable(): boolean {
    const projectId = this.configService.get<string>('FIREBASE_PROJECT_ID');
    const privateKey = this.configService.get<string>('FIREBASE_PRIVATE_KEY');
    const clientEmail = this.configService.get<string>('FIREBASE_CLIENT_EMAIL');

    this.credentialsAvailable = !!projectId && !!privateKey && !!clientEmail;
    return this.credentialsAvailable;
  }

  private initializeFirebase() {
    // Lazy initialization - only when needed
    if (this.initializationAttempted) {
      return;
    }

    this.initializationAttempted = true;

    const projectId = this.configService.get<string>('FIREBASE_PROJECT_ID');
    const privateKey = this.configService
      .get<string>('FIREBASE_PRIVATE_KEY')
      ?.replace(/\\n/g, '\n');
    const clientEmail = this.configService.get<string>('FIREBASE_CLIENT_EMAIL');

    if (!projectId || !privateKey || !clientEmail) {
      console.error(
        '❌ Firebase credentials are missing in environment variables. Firebase auth is disabled.',
      );
      throw new UnauthorizedException(
        'Firebase credentials are not configured. Please set FIREBASE_PROJECT_ID, FIREBASE_PRIVATE_KEY, and FIREBASE_CLIENT_EMAIL in environment variables.',
      );
    }

    try {
      this.firebaseApp = admin.initializeApp(
        {
          credential: admin.credential.cert({
            projectId,
            privateKey,
            clientEmail,
          } as any),
        },
        'firebase-auth',
      );
    } catch (error: any) {
      if (!error.message.includes('already exists')) {
        throw error;
      }
      // Use existing app if already initialized
      this.firebaseApp = admin.app('firebase-auth');
    }
  }

  async verifyFirebaseToken(token: string) {
    if (!token || typeof token !== 'string' || token.trim() === '') {
      throw new UnauthorizedException(
        'Firebase token is required and must be a non-empty string',
      );
    }

    if (!this.credentialsAvailable) {
      throw new UnauthorizedException(
        'Firebase is not configured. Please set FIREBASE_PROJECT_ID, FIREBASE_PRIVATE_KEY, and FIREBASE_CLIENT_EMAIL.',
      );
    }

    this.initializeFirebase();

    try {
      if (!this.firebaseApp) {
        throw new Error('Firebase app failed to initialize');
      }

      const decodedToken = await admin
        .auth(this.firebaseApp)
        .verifyIdToken(token);

      return {
        uid: decodedToken.uid,
        email: decodedToken.email,
        name: decodedToken.name,
        picture: decodedToken.picture,
        emailVerified: decodedToken.email_verified,
        provider: decodedToken.firebase?.sign_in_provider || 'unknown',
      };
    } catch (error: any) {
      console.error('❌ Token verification failed:', error);

      // Provide detailed error messages based on error type
      if (error.code === 'auth/argument-error') {
        throw new UnauthorizedException(
          'Invalid Firebase token format. Token must be a valid Firebase ID token.',
        );
      }
      if (error.code === 'auth/invalid-id-token') {
        throw new UnauthorizedException(
          'Firebase token is invalid. Please provide a valid Firebase ID token.',
        );
      }
      if (error.code === 'auth/id-token-expired') {
        throw new UnauthorizedException(
          'Firebase token has expired. Please sign in again to get a new token.',
        );
      }
      if (error.message?.includes('decode')) {
        throw new UnauthorizedException(
          'Firebase token is malformed and cannot be decoded. Please check the token format.',
        );
      }
      if (error.message?.includes('verify')) {
        throw new UnauthorizedException(
          'Firebase token verification failed. Token may be invalid, expired, or tampered with.',
        );
      }

      throw new UnauthorizedException(
        `Firebase authentication failed: ${error.message || 'Invalid or expired Firebase token'}`,
      );
    }
  }
}
