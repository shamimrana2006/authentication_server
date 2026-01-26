import { Injectable, UnauthorizedException } from '@nestjs/common';
import * as admin from 'firebase-admin';
import { ConfigService } from '@nestjs/config';

@Injectable()
export class FirebaseAuthService {
  private firebaseApp: admin.app.App;

  constructor(private configService: ConfigService) {
    this.initializeFirebase();
  }

  private initializeFirebase() {
    const projectId = this.configService.get<string>('FIREBASE_PROJECT_ID');
    const privateKey = this.configService
      .get<string>('FIREBASE_PRIVATE_KEY')
      ?.replace(/\\n/g, '\n');
    const clientEmail = this.configService.get<string>('FIREBASE_CLIENT_EMAIL');

    if (!projectId || !privateKey || !clientEmail) {
      console.error(
        '❌ Firebase credentials are missing in environment variables',
      );
      throw new Error(
        'Firebase credentials are missing in environment variables',
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
    try {
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
    } catch (error) {
      console.error('❌ Token verification failed:', error);
      throw new UnauthorizedException('Invalid or expired Firebase token');
    }
  }
}
