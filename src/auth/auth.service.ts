import {
  Injectable,
  UnauthorizedException,
  BadRequestException,
  NotFoundException,
} from '@nestjs/common';
import { registerDto } from './dto/register.dto';
import { UserService } from '../user/user.service';
import { compareHash, hashText } from '@/common/hashText';
import { generateStrongPassword } from '@/common/password-generator';
import { PrismaService } from '@/lib/prisma/prisma.service';
import { loginDto } from './dto/login.dto';
import { JwtService } from '@nestjs/jwt';
import { EmailService } from '../email/email.service';
import { VerifyEmailDto } from './dto/verify-email.dto';
import { ResendOtpDto } from './dto/resend-otp.dto';
import { ForgotPasswordDto } from './dto/forgot-password.dto';
import { VerifyResetOtpDto } from './dto/verify-reset-otp.dto';
import { ResetPasswordDto } from './dto/reset-password.dto';
import { ChangePasswordDto } from './dto/change-password.dto';
import { CheckUsernameDto } from './dto/check-username.dto';
import { UpdateUsernameDto } from './dto/update-username.dto';
import { UpdateProfileDto } from './dto/update-profile.dto';
import { ConfigService } from '@nestjs/config';
import { FirebaseAuthService } from './services/firebase-auth.service';

@Injectable()
export class AuthService {
  constructor(
    private readonly userService: UserService,
    private Prisma: PrismaService,
    private jwtService: JwtService,
    private emailService: EmailService,
    private configService: ConfigService,
    private firebaseAuthService: FirebaseAuthService,
  ) {}

  async validateUser(emailOrUsername: string, password: string): Promise<any> {
    const user: any = await this.Prisma.client.user.findFirst({
      where: {
        OR: [{ email: emailOrUsername }, { username: emailOrUsername }],
      },
    });

    if (!user) {
      return null;
    }

    const isPasswordValid = await compareHash(password, user.password);
    if (isPasswordValid) {
      const { password, ...result } = user;
      return result;
    }
    throw new Error('Invalid credentials');
  }

  async Register(createAuthDto: registerDto) {
    const existingUser = await this.Prisma.client.user.findFirst({
      where: {
        OR: [
          { email: createAuthDto.email },
          { username: createAuthDto.username },
        ],
      },
    });
    if (existingUser) {
      return {
        success: false,
        message: `Email${createAuthDto.username ? '/Username' : ''} already in use in another account`,
      };
    }

    // create a unique username if not provided and if provided check uniqueness

    let username = createAuthDto.username
      ? createAuthDto.username.trim().toLowerCase().replace(/\s+/g, '')
      : createAuthDto.name.trim().toLowerCase().replace(/\s+/g, '');
    let isUnique = false;

    while (!isUnique) {
      const exists = await this.Prisma.client.user.findUnique({
        where: { username },
      });

      if (!exists) {
        isUnique = true;
      } else {
        username = `${username}${Math.floor(Math.random() * 100000)}`;
      }
    }

    const passwordHash = await hashText(createAuthDto.password);

    // Generate OTP for email verification
    const otp = this.generateOtp();
    const otpExpiry = new Date(Date.now() + 10 * 60 * 1000); // 10 minutes

    const payload = {
      ...createAuthDto,
      password: passwordHash,
      username,
      emailVerificationOtp: otp,
      emailVerificationExpiry: otpExpiry,
    };

    // Send verification email if required
    const verificationRequired = this.configService.get<string>(
      'EMAIL_VERIFICATION_REQUIRED',
    );
    if (verificationRequired === 'true') {
      await this.emailService.sendVerificationOtp(
        createAuthDto.email,
        otp,
        createAuthDto.name || 'User',
      );
    }
    const user = await this.Prisma.client.user.create({
      data: payload,
    });

    const { password, ...userWithoutPassword } = user;
    return {
      success: true,
      message:
        'User registered successfully. Please check your email for verification code.',
      data: {
        ...userWithoutPassword,
      },
    };
  }

  async login(body: loginDto, user: any) {
    const { password, ...userWithoutPassword } = user;

    const verificationRequired = this.configService.get<string>(
      'EMAIL_VERIFICATION_REQUIRED',
    );
    if (verificationRequired === 'true') {
      // Check if email verification is required
      if (!user.emailVerified) {
        throw new UnauthorizedException(
          'Please verify your email before logging in',
        );
      }
    }

    // Generate tokens
    const tokens = await this.generateTokens(userWithoutPassword);

    return {
      ...tokens,
      user: userWithoutPassword,
    };
  }

  async generateTokens(user: any) {
    const accessTokenExpiration =
      //convert day from milliseconds
      Number(this.configService.get<string>('ACCESS_TOKEN_EXPIRATION_MS')) /
        86400000 || 15; // 15 minutes
    const refreshTokenExpiration =
      //convert days from milliseconds
      Number(this.configService.get<string>('REFRESH_TOKEN_EXPIRATION_MS')) /
        86400000 || 7;

    // Minimal token payload - only essential claims
    const tokenPayload = {
      id: user.id,
      email: user.email,
      name: user.name,
      role: user.role,
    };

    const accessToken = this.jwtService.sign(tokenPayload, {
      expiresIn: `${accessTokenExpiration}d`,
      // expiresIn: this.configService.get<string>('ACCESS_TOKEN_EXPIRATION_MS'),
    } as any);

    const refreshToken = this.jwtService.sign(tokenPayload, {
      expiresIn: `${refreshTokenExpiration}d`,
      // expiresIn: this.configService.get<string>('REFRESH_TOKEN_EXPIRATION_MS'),
    } as any);

    return {
      access_token: accessToken,
      refresh_token: refreshToken,
    };
  }

  async generateRefreshTokenOnly(user: any, oldRefreshToken?: string) {
    const refreshTokenExpiration =
      Number(this.configService.get<string>('REFRESH_TOKEN_EXPIRATION_MS')) /
        86400000 || 7;

    // Minimal token payload - only essential claims
    const tokenPayload = {
      id: user.id,
      email: user.email,
      name: user.name,
      role: user.role,
    };

    const refreshToken = this.jwtService.sign(tokenPayload, {
      expiresIn: this.configService.get<string>('REFRESH_TOKEN_EXPIRATION_MS'),
    } as any);

    return refreshToken;
  }

  async generateAccessTokenOnly(user: any) {
    // Minimal token payload - only essential claims
    const tokenPayload = {
      id: user.id,
      email: user.email,
      name: user.name,
      role: user.role,
    };

    const accessToken = this.jwtService.sign(tokenPayload, {
      expiresIn: this.configService.get<string>('ACCESS_TOKEN_EXPIRATION_MS'),
    } as any);

    return accessToken;
  }

  async validateRefreshToken(userId: string, refreshToken: string) {
    if (!refreshToken) return false;
    const session = await this.Prisma.client.session.findFirst({
      where: {
        userId,
        refreshToken,
      },
    });

    if (!session || session.expiresAt < new Date()) {
      return false;
    }
    return true;
  }

  async logout(userId: string) {
    await this.Prisma.client.session.deleteMany({
      where: {
        userId,
      },
    });

    return {
      success: true,
      message: 'Logged out successfully',
      userId,
    };
  }

  async logoutAll(userId: string) {
    await this.Prisma.client.session.deleteMany({
      where: { userId },
    });

    return {
      success: true,
      message: 'Logged out from all devices',
    };
  }

  async refreshToken(refreshToken: string) {
    const session = await this.Prisma.client.session.findUnique({
      where: { refreshToken },
      include: { user: true },
    });

    if (!session || session.expiresAt < new Date()) {
      throw new UnauthorizedException('Invalid or expired refresh token');
    }

    // Delete old session (Token Rotation)
    await this.Prisma.client.session.delete({
      where: { id: session.id },
    });

    const { password, ...userWithoutPassword } = session.user;
    const tokens = await this.generateTokens(userWithoutPassword);

    return {
      ...tokens,
      user: userWithoutPassword,
    };
  }

  // OTP Helper
  private generateOtp(): string {
    return Math.floor(100000 + Math.random() * 900000).toString();
  }

  // Email Verification
  async verifyEmail(dto: VerifyEmailDto) {
    const user = await this.Prisma.client.user.findUnique({
      where: { email: dto.email },
    });

    if (!user) {
      throw new NotFoundException('User not found');
    }

    if (user.emailVerified) {
      return {
        success: false,
        message: 'Email already verified',
      };
    }

    if (
      !user.emailVerificationOtp ||
      user.emailVerificationOtp !== dto.otp ||
      !user.emailVerificationExpiry ||
      user.emailVerificationExpiry < new Date()
    ) {
      throw new BadRequestException('Invalid or expired OTP');
    }

    await this.Prisma.client.user.update({
      where: { id: user.id },
      data: {
        emailVerified: true,
        emailVerificationOtp: null,
        emailVerificationExpiry: null,
      },
    });

    return {
      success: true,
      message: 'Email verified successfully',
    };
  }

  async resendVerificationOtp(dto: ResendOtpDto) {
    const user = await this.Prisma.client.user.findUnique({
      where: { email: dto.email },
    });

    if (!user) {
      throw new NotFoundException('User not found');
    }

    if (user.emailVerified) {
      return {
        success: false,
        message: 'Email already verified',
      };
    }

    const otp = this.generateOtp();
    const otpExpiry = new Date(Date.now() + 10 * 60 * 1000);

    await this.Prisma.client.user.update({
      where: { id: user.id },
      data: {
        emailVerificationOtp: otp,
        emailVerificationExpiry: otpExpiry,
      },
    });

    await this.emailService.sendVerificationOtp(
      user.email,
      otp,
      user.name || 'User',
    );

    return {
      success: true,
      message: 'Verification OTP sent successfully',
    };
  }

  // Password Reset
  async forgotPassword(dto: ForgotPasswordDto) {
    const user = await this.Prisma.client.user.findUnique({
      where: { email: dto.email },
    });

    if (!user) {
      // Don't reveal if user exists
      return {
        success: true,
        message: 'user not found',
      };
    }

    const otp = this.generateOtp();
    const otpExpiry = new Date(Date.now() + 10 * 60 * 1000);

    await this.Prisma.client.user.update({
      where: { id: user.id },
      data: {
        resetPasswordOtp: otp,
        resetPasswordOtpExpiry: otpExpiry,
        resetPasswordVerified: false,
      },
    });

    await this.emailService.sendPasswordResetOtp(
      user.email,
      otp,
      user.name || 'User',
    );

    return {
      success: true,
      message: 'Password reset OTP sent successfully',
    };
  }

  async verifyResetOtp(dto: VerifyResetOtpDto) {
    const user = await this.Prisma.client.user.findUnique({
      where: { email: dto.email },
    });

    if (!user) {
      throw new NotFoundException('User not found');
    }

    if (
      !user.resetPasswordOtp ||
      user.resetPasswordOtp !== dto.otp ||
      !user.resetPasswordOtpExpiry ||
      user.resetPasswordOtpExpiry < new Date()
    ) {
      throw new BadRequestException('Invalid or expired OTP');
    }

    await this.Prisma.client.user.update({
      where: { id: user.id },
      data: {
        resetPasswordVerified: true,
      },
    });

    return {
      success: true,
      message: 'OTP verified successfully. You can now reset your password.',
    };
  }

  async resetPassword(dto: ResetPasswordDto) {
    const user = await this.Prisma.client.user.findUnique({
      where: { email: dto.email },
    });

    if (!user) {
      throw new NotFoundException('User not found');
    }

    if (!user.resetPasswordVerified) {
      throw new BadRequestException('Please verify OTP first');
    }

    const passwordHash = await hashText(dto.newPassword);

    await this.Prisma.client.user.update({
      where: { id: user.id },
      data: {
        password: passwordHash,
        resetPasswordOtp: null,
        resetPasswordOtpExpiry: null,
        resetPasswordVerified: false,
      },
    });

    // Logout from all devices
    await this.Prisma.client.session.deleteMany({
      where: { userId: user.id },
    });

    await this.emailService.sendPasswordChangedNotification(
      user.email,
      user.name || 'User',
    );

    return {
      success: true,
      message: 'Password reset successfully',
    };
  }

  async resendResetOtp(dto: ResendOtpDto) {
    const user = await this.Prisma.client.user.findUnique({
      where: { email: dto.email },
    });

    if (!user) {
      throw new NotFoundException('User not found');
    }

    const otp = this.generateOtp();
    const otpExpiry = new Date(Date.now() + 10 * 60 * 1000);

    await this.Prisma.client.user.update({
      where: { id: user.id },
      data: {
        resetPasswordOtp: otp,
        resetPasswordOtpExpiry: otpExpiry,
        resetPasswordVerified: false,
      },
    });

    await this.emailService.sendPasswordResetOtp(
      user.email,
      otp,
      user.name || 'User',
    );

    return {
      success: true,
      message: 'Reset OTP sent successfully',
    };
  }

  async changePassword(userId: string, dto: ChangePasswordDto) {
    const user = await this.Prisma.client.user.findUnique({
      where: { id: userId },
    });

    if (!user || !user.password) {
      throw new NotFoundException('User not found or no password set');
    }

    const isPasswordValid = await compareHash(
      dto.currentPassword,
      user.password,
    );

    if (!isPasswordValid) {
      throw new BadRequestException('Current password is incorrect');
    }

    const passwordHash = await hashText(dto.newPassword);

    await this.Prisma.client.user.update({
      where: { id: user.id },
      data: { password: passwordHash },
    });

    await this.emailService.sendPasswordChangedNotification(
      user.email,
      user.name || 'User',
    );

    return {
      success: true,
      message: 'Password changed successfully',
    };
  }

  // Username Management
  async checkUsername(dto: CheckUsernameDto, userId?: string) {
    const user = await this.Prisma.client.user.findUnique({
      where: { username: dto.username },
    });

    if (userId && user && user.id === userId) {
      return {
        available: true,
        message: 'you already own this username',
      };
    }

    return {
      available: !user,
      message: user ? 'Username already taken' : 'Username is available',
    };
  }

  async updateUsername(userId: string, dto: UpdateUsernameDto) {
    const existingUser = await this.Prisma.client.user.findUnique({
      where: { username: dto.username },
    });

    const youOwnThisUsername = existingUser && existingUser.id === userId;
    if (youOwnThisUsername) {
      return {
        success: true,
        message: 'You already own this username',
      };
    }

    if (existingUser && existingUser.id !== userId) {
      throw new BadRequestException('Username already taken');
    }

    await this.Prisma.client.user.update({
      where: { id: userId },
      data: { username: dto.username },
    });

    return {
      success: true,
      message: 'Username updated successfully',
    };
  }

  async forgotUsername(email: string) {
    const user = await this.Prisma.client.user.findUnique({
      where: { email },
    });

    if (!user) {
      // Don't reveal if user exists
      return {
        success: true,
        message: 'If the email exists, username has been sent',
      };
    }

    if (!user.username) {
      return {
        success: false,
        message: 'No username set for this account',
      };
    }

    await this.emailService.sendUsernameReminder(
      user.email,
      user.username,
      user.name || 'User',
    );

    return {
      success: true,
      message: 'Username sent to your email',
    };
  }

  // Profile Management
  async getMe(userId: string) {
    const user = await this.Prisma.client.user.findUnique({
      where: { id: userId },
      omit: {
        password: true,
        emailVerificationOtp: true,
        emailVerificationExpiry: true,
        resetPasswordOtp: true,
        resetPasswordOtpExpiry: true,
      },
    });

    if (!user) {
      throw new NotFoundException('User not found');
    }

    return user;
  }

  async updateProfile(userId: string, dto: UpdateProfileDto) {
    await this.Prisma.client.user.update({
      where: { id: userId },
      data: dto,
    });

    return {
      success: true,
      message: 'Profile updated successfully',
    };
  }

  async getSessions(userId: string) {
    const sessions = await this.Prisma.client.session.findMany({
      where: { userId },
      select: {
        id: true,
        deviceInfo: true,
        ipAddress: true,
        createdAt: true,
        lastActivity: true,
        expiresAt: true,
      },
      orderBy: { lastActivity: 'desc' },
    });

    return sessions;
  }

  // ==================== Firebase OAuth (Google, Apple, Facebook, GitHub, etc.) ====================

  async verifyFirebaseToken(token: string) {
    try {
      if (!token) {
        throw new UnauthorizedException('Firebase token is required');
      }
      const firebaseUserData =
        await this.firebaseAuthService.verifyFirebaseToken(token);
      return await this.firebaseAuthCallback(firebaseUserData);
    } catch (error: any) {
      console.error('❌ Firebase token verification error:', error);
      // Pass through the detailed error message from firebase-auth.service
      throw error;
    }
  }

  async firebaseAuthCallback(firebaseUserData: any) {
    try {
      // Check if user exists with Google ID or email
      let user = await this.Prisma.client.user.findFirst({
        where: {
          OR: [
            { googleId: firebaseUserData.uid },
            { email: firebaseUserData.email },
          ],
        },
      });

      const isNewUser = !user;
      let generatedPassword: string | null = null;

      // If user doesn't exist, create new user
      if (!user) {
        // Generate strong password
        generatedPassword = generateStrongPassword();
        const passwordHash = await hashText(generatedPassword);

        const username = await this.generateUniqueUsername(
          firebaseUserData.name || 'user',
        );

        user = await this.Prisma.client.user.create({
          data: {
            id: this.generateUserId(),
            email: firebaseUserData.email,
            name: firebaseUserData.name || 'User',
            avatar:
              firebaseUserData.picture ||
              'https://i.pinimg.com/236x/1a/a8/d7/1aa8d75f3498784bcd2617b3e3d1e0c4.jpg',
            googleId: firebaseUserData.uid,
            emailVerified: firebaseUserData.emailVerified || true,
            username,
            password: passwordHash, // Store hashed password
          },
        });

        // Send password email to new user
        try {
          await this.emailService.sendGoogleAuthPassword(
            user.email,
            generatedPassword,
            user.username || 'User',
            user.name || 'User',
          );
        } catch (emailError) {
          console.error('⚠️ Failed to send password email:', emailError);
          // Don't throw - user was created successfully, email failure is not critical
        }
      } else if (!user.googleId) {
        // Link Google ID to existing user
        user = await this.Prisma.client.user.update({
          where: { id: user.id },
          data: {
            googleId: firebaseUserData.uid,
            emailVerified: true,
          },
        });
      }

      // Remove password from response
      const { password, ...userWithoutPassword } = user;

      // Generate tokens
      const tokens = await this.generateTokens(userWithoutPassword);

      return {
        success: true,
        message: isNewUser
          ? 'Account created successfully. Check your email for password details.'
          : user.googleId === firebaseUserData.uid
            ? 'Login successful'
            : 'Account linked successfully',
        access_token: tokens.access_token,
        refresh_token: tokens.refresh_token,
        user: userWithoutPassword,
      };
    } catch (error) {
      console.error('❌ Firebase auth callback error:', error);
      throw error;
    }
  }

  private async generateUniqueUsername(baseName: string): Promise<string> {
    let username = baseName.trim().toLowerCase().replace(/\s+/g, '');
    let isUnique = false;
    let attempt = 0;

    while (!isUnique && attempt < 10) {
      const exists = await this.Prisma.client.user.findUnique({
        where: { username },
      });

      if (!exists) {
        isUnique = true;
      } else {
        username = `${baseName.toLowerCase().replace(/\s+/g, '')}${Math.floor(Math.random() * 10000)}`;
        attempt++;
      }
    }

    return username;
  }

  // ==================== Discord OAuth ====================

  async discordAuthCallback(discordUserData: any) {
    try {
      // Check if user exists with Discord ID or email
      let user = await this.Prisma.client.user.findFirst({
        where: {
          OR: [
            { discord: discordUserData.discordId },
            { email: discordUserData.email },
          ],
        },
      });

      const isNewUser = !user;
      let generatedPassword: string | null = null;

      // If user doesn't exist, create new user
      if (!user) {
        // Generate strong password
        generatedPassword = generateStrongPassword();
        const passwordHash = await hashText(generatedPassword);

        const username = await this.generateUniqueUsername(
          discordUserData.username || 'user',
        );

        user = await this.Prisma.client.user.create({
          data: {
            id: this.generateUserId(),
            email: discordUserData.email,
            name:
              discordUserData.name ||
              discordUserData.username ||
              'Discord User',
            avatar: discordUserData.avatar,
            discord: discordUserData.discordId,
            emailVerified: true, // Discord verifies emails
            username,
            password: passwordHash, // Store hashed password
          },
        });

        // Send password email to new user
        try {
          await this.emailService.sendGoogleAuthPassword(
            user.email,
            generatedPassword,
            user.username || 'User',
            user.name || 'User',
          );
        } catch (emailError) {
          console.error('⚠️ Failed to send password email:', emailError);
          // Don't throw - user was created successfully, email failure is not critical
        }
      } else if (!user.discord) {
        // Link Discord ID to existing user
        user = await this.Prisma.client.user.update({
          where: { id: user.id },
          data: {
            discord: discordUserData.discordId,
            emailVerified: true,
          },
        });
      }

      // Remove password from response
      const { password, ...userWithoutPassword } = user;

      // Generate tokens
      const tokens = await this.generateTokens(userWithoutPassword);

      return {
        success: true,
        message: isNewUser
          ? 'Account created successfully. Check your email for password details.'
          : user.discord === discordUserData.discordId
            ? 'Login successful'
            : 'Account linked successfully',
        access_token: tokens.access_token,
        refresh_token: tokens.refresh_token,
        user: userWithoutPassword,
      };
    } catch (error) {
      console.error('❌ Discord auth callback error:', error);
      throw error;
    }
  }

  private generateUserId(): string {
    return `user_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;
  }
}
