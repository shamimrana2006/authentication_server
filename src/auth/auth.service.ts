import {
  Injectable,
  UnauthorizedException,
  BadRequestException,
  NotFoundException,
} from '@nestjs/common';
import { registerDto } from './dto/register.dto';
import { UserService } from '../user/user.service';
import { compareHash, hashText } from '@/common/hashText';
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

@Injectable()
export class AuthService {
  constructor(
    private readonly userService: UserService,
    private Prisma: PrismaService,
    private jwtService: JwtService,
    private emailService: EmailService,
    private configService: ConfigService,
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

    let username = createAuthDto.name.trim().toLowerCase().replace(/\s+/g, '');
    let isUnique = false;

    while (!isUnique) {
      const exists = await this.Prisma.client.user.findUnique({
        where: { username },
      });
      console.log(username);

      if (!exists) {
        isUnique = true;
      } else {
        // example: johndoe65454

        username = `${username}${Math.floor(Math.random() * 100000)}`;
      }
    }

    const passwordHash = await hashText(createAuthDto.password);

    console.log(createAuthDto.password, passwordHash);

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

    // Send verification email
    await this.emailService.sendVerificationOtp(
      createAuthDto.email,
      otp,
      createAuthDto.name || 'User',
    );

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
      // Check if email is verified
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
      Number(this.configService.get<string>('ACCESS_TOKEN_EXPIRATION_M')) || 15; // 15 minutes
    const refreshTokenExpiration =
      Number(this.configService.get<string>('REFRESH_TOKEN_EXPIRATION_DD')) ||
      7;
    // const refreshTokenExpirationDays = Number(this.configService.get<string>('REFRESH_TOKEN_EXPIRATION_DD')) || 7;
    const accessToken = this.jwtService.sign(user, {
      // expiresIn: `${accessTokenExpiration}m`,
      expiresIn: '10s',
    } as any);

    const refreshToken = this.jwtService.sign(user, {
      // expiresIn: `${refreshTokenExpiration}d`,
      expiresIn: '20s',
    } as any);

    // Store refresh token in session
    await this.Prisma.client.session.create({
      data: {
        userId: user.id,
        refreshToken,
        expiresAt: new Date(
          Date.now() + refreshTokenExpiration * 24 * 60 * 60 * 1000,
        ),
      },
    });

    return {
      access_token: accessToken,
      refresh_token: refreshToken,
    };
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

  async logout(userId: string, refreshToken: string) {
    await this.Prisma.client.session.deleteMany({
      where: {
        userId,
        refreshToken,
      },
    });

    return {
      success: true,
      message: 'Logged out successfully',
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
        message: 'If the email exists, a reset code has been sent',
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
      select: {
        id: true,
        email: true,
        username: true,
        name: true,
        avatar: true,
        emailVerified: true,
        role: true,
        createdAt: true,
        updatedAt: true,
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
}
