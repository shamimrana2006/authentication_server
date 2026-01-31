import {
  Controller,
  Post,
  Body,
  UseGuards,
  Req,
  Res,
  Get,
  Put,
  Delete,
} from '@nestjs/common';
import { AuthService } from './auth.service';
import { registerDto } from './dto/register.dto';
import { ApiTags, ApiBearerAuth, ApiOperation } from '@nestjs/swagger';
import { AuthGuard } from '@nestjs/passport';
import { loginDto } from './dto/login.dto';
import { FirebaseAuthDto } from './dto/firebase-auth.dto';
import { VerifyEmailDto } from './dto/verify-email.dto';
import { ResendOtpDto } from './dto/resend-otp.dto';
import { ForgotPasswordDto } from './dto/forgot-password.dto';
import { VerifyResetOtpDto } from './dto/verify-reset-otp.dto';
import { ResetPasswordDto } from './dto/reset-password.dto';
import { ChangePasswordDto } from './dto/change-password.dto';
import { CheckUsernameDto } from './dto/check-username.dto';
import { UpdateUsernameDto } from './dto/update-username.dto';
import { UpdateProfileDto } from './dto/update-profile.dto';
import { RefreshTokenDto } from './dto/refresh-token.dto';
import { ConfigService } from '@nestjs/config';
import {
  ValidUser,
  ValidAdmin,
  ValidAll,
} from '@/common/decorators/validate.decorator';

@ApiTags('auth')
@Controller('auth')
export class AuthController {
  constructor(
    private readonly authService: AuthService,
    private readonly configService: ConfigService,
  ) {}

  //Grobal token expiration settings

  // ==================== Registration & Login ====================

  @Post('register')
  @ApiOperation({ summary: 'Register a new user and send verification email' })
  Register(@Body() createAuthDto: registerDto) {
    return this.authService.Register(createAuthDto);
  }

  @Post('login')
  @UseGuards(AuthGuard('local'))
  @ApiOperation({
    summary:
      'Login with email/username and password (sets cookies + returns tokens in headers)',
  })
  async login(
    @Body() body: loginDto,
    @Req() req: any,
    @Res({ passthrough: true }) res: any,
  ) {
    const result = await this.authService.login(body, req.user);

    const isProduction = process.env.NODE_ENV === 'production';
    const accessTokenConfigMs = Number(
      this.configService.get('ACCESS_TOKEN_EXPIRATION_MS'),
    );
    const refreshTokenConfigMs = Number(
      this.configService.get('REFRESH_TOKEN_EXPIRATION_MS'),
    );
    const accessTokenExpirMs = Math.floor(
      isNaN(accessTokenConfigMs) ? 15 * 60 * 1000 : accessTokenConfigMs,
    );
    const refreshTokenExpirMs = Math.floor(
      isNaN(refreshTokenConfigMs)
        ? 7 * 24 * 60 * 60 * 1000
        : refreshTokenConfigMs,
    );

    // Set cookies for automatic token management
    res.cookie('access_token', result.access_token, {
      httpOnly: false, // Allow JavaScript access in dev for Swagger
      secure: isProduction,
      sameSite: 'lax',
      maxAge: accessTokenExpirMs, // 15 seconds
    });

    res.cookie('refresh_token', result.refresh_token, {
      httpOnly: false, // Allow JavaScript access in dev for Swagger
      secure: isProduction,
      sameSite: 'lax',
      maxAge: refreshTokenExpirMs, // 20 seconds
    });

    // Also send tokens in response headers for easy copy-paste in Swagger
    res.setHeader('X-Access-Token', result.access_token);
    res.setHeader('X-Refresh-Token', result.refresh_token);

    return result;
  }

  @Post('firebase-login')
  @ApiOperation({
    summary:
      'Firebase Social Login/Register - Supports Google, Apple, Facebook, GitHub, etc.',
    description:
      'Universal social login endpoint using Firebase Authentication. Send Firebase ID Token from any supported provider (Google, Apple, Facebook, GitHub, etc.). Automatically creates user account if not exists.',
  })
  async firebaseLogin(
    @Body() dto: FirebaseAuthDto,
    @Res({ passthrough: true }) res: any,
  ) {
    try {
      const result = await this.authService.verifyFirebaseToken(dto.token);

      const isProduction = process.env.NODE_ENV === 'production';
      const accessTokenConfigMs = Number(
        this.configService.get('ACCESS_TOKEN_EXPIRATION_MS'),
      );
      const refreshTokenConfigMs = Number(
        this.configService.get('REFRESH_TOKEN_EXPIRATION_MS'),
      );
      const accessTokenExpirMs = Math.floor(
        isNaN(accessTokenConfigMs) ? 15 * 60 * 1000 : accessTokenConfigMs,
      );
      const refreshTokenExpirMs = Math.floor( 
        isNaN(refreshTokenConfigMs)
          ? 7 * 24 * 60 * 60 * 1000
          : refreshTokenConfigMs,
      );

      // Set cookies
      res.cookie('access_token', result.access_token, {
        httpOnly: false,
        secure: isProduction,
        sameSite: 'lax',
        maxAge: accessTokenExpirMs,
      });

      res.cookie('refresh_token', result.refresh_token, {
        httpOnly: false,
        secure: isProduction,
        sameSite: 'lax',
        maxAge: refreshTokenExpirMs,
      });

      // Also send tokens in response headers
      res.setHeader('X-Access-Token', result.access_token);
      res.setHeader('X-Refresh-Token', result.refresh_token);

      return {
        success: true,
        message: result.message || 'Social authentication successful',
        access_token: result?.access_token,
        refresh_token: result?.refresh_token,
        user: result?.user,
      };
    } catch (error) {
      throw error;
    }
  }

  @Get('me')
  @ValidUser()
  @ApiBearerAuth('JWT-auth')
  @ApiBearerAuth('refresh-token')
  @ApiOperation({
    summary: 'Get current user profile (supports auto token refresh)',
  })
  async getMe(@Req() req: any, @Res({ passthrough: true }) res: any) {
    const result = await this.authService.getMe(req.user.id);
    req.user = result;
    return {
      success: true,
      message: 'successfully fetched user profile',
      user: req.user,
      accessToken: res.locals?.activeAccessToken,
      refreshToken: res.locals?.activeRefreshToken,
    };
  }

  @Delete('logout')
  @ValidUser()
  @ApiBearerAuth('JWT-auth')
  @ApiBearerAuth('refresh-token')
  @ApiOperation({ summary: 'Logout from current device (clears cookies)' })
  async logout(
    @Body() body: any,
    @Req() req: any,
    @Res({ passthrough: true }) res: any,
  ) {
    res.clearCookie('access_token');
    res.clearCookie('refresh_token');
    const result = await this.authService.logout(req.user.id);

    // Clear cookies on logout

    return result;
  }

  // @Post('refresh-token')
  // @ApiOperation({
  //   summary:
  //     'Refresh access token using refresh token (returns new tokens + sets cookies)',
  // })
  // async refreshToken(
  //   @Body() body: RefreshTokenDto,
  //   @Res({ passthrough: true }) res: any,
  // ) {
  //   const result = await this.authService.refreshToken(body.refreshToken);

  //   const isProduction = process.env.NODE_ENV === 'production';

  //   // Update cookies with new tokens - use config values for expiration
  //   const accessTokenExpirMs =
  //     this.configService.get<number>('ACCESS_TOKEN_EXPIRATION_MS') ||
  //     15 * 60 * 1000;
  //   const refreshTokenExpirMs =
  //     this.configService.get<number>('REFRESH_TOKEN_EXPIRATION_MS') ||
  //     7 * 24 * 60 * 60 * 1000;

  //   res.cookie('access_token', result.access_token, {
  //     httpOnly: false,
  //     secure: isProduction,
  //     sameSite: 'lax',
  //     maxAge: accessTokenExpirMs,
  //   });

  //   res.cookie('refresh_token', result.refresh_token, {
  //     httpOnly: false,
  //     secure: isProduction,
  //     sameSite: 'lax',
  //     maxAge: refreshTokenExpirMs,
  //   });

  //   // Send in headers for easy access
  //   res.setHeader('X-Access-Token', result.access_token);
  //   res.setHeader('X-Refresh-Token', result.refresh_token);

  //   // Return tokens explicitly in response body for Swagger visibility
  //   return {
  //     access_token: result?.access_token,
  //     refresh_token: result?.refresh_token,
  //     user: result?.user,
  //     message: 'Tokens refreshed successfully',
  //     success: true,
  //   };
  // }

  // ==================== Email Verification ====================

  @Post('verify-email')
  @ApiOperation({ summary: 'Verify email with OTP' })
  verifyEmail(@Body() dto: VerifyEmailDto) {
    return this.authService.verifyEmail(dto);
  }

  @Post('resend-verification-otp')
  @ApiOperation({ summary: 'Resend verification OTP' })
  resendVerificationOtp(@Body() dto: ResendOtpDto) {
    return this.authService.resendVerificationOtp(dto);
  }

  // ==================== Password Management ====================

  @Post('forgot-password')
  @ApiOperation({ summary: 'Send password reset OTP to email' })
  forgotPassword(@Body() dto: ForgotPasswordDto) {
    return this.authService.forgotPassword(dto);
  }

  @Post('verify-reset-otp')
  @ApiOperation({ summary: 'Verify password reset OTP' })
  verifyResetOtp(@Body() dto: VerifyResetOtpDto) {
    return this.authService.verifyResetOtp(dto);
  }

  @Post('reset-password')
  @ApiOperation({ summary: 'Reset password with verified OTP' })
  resetPassword(@Body() dto: ResetPasswordDto) {
    return this.authService.resetPassword(dto);
  }

  // @Post('resend-reset-otp')
  // @ApiOperation({ summary: 'Resend password reset OTP' })
  // resendResetOtp(@Body() dto: ResendOtpDto) {
  //   return this.authService.resendResetOtp(dto);
  // }

  @Put('change-password')
  @ValidUser()
  @ApiBearerAuth('JWT-auth')
  @ApiBearerAuth('refresh-token')
  @ApiOperation({ summary: 'Change password when logged in' })
  changePassword(@Body() dto: ChangePasswordDto, @Req() req: any) {
    return this.authService.changePassword(req.user.id, dto);
  }

  // ==================== Username Management ====================

  @Post('check-username')
  @ValidAll()
  @ApiBearerAuth('JWT-auth')
  @ApiBearerAuth('refresh-token')
  @ApiOperation({ summary: 'Check if username is available (optional auth)' })
  checkUsername(@Body() dto: CheckUsernameDto, @Req() req: any) {
    return this.authService.checkUsername(dto, req.user?.id);
  }

  @Put('update-username')
  @ValidUser()
  @ApiBearerAuth('JWT-auth')
  @ApiBearerAuth('refresh-token')
  @ApiOperation({ summary: 'Update username' })
  updateUsername(@Body() dto: UpdateUsernameDto, @Req() req: any) {
    return this.authService.updateUsername(req.user.id, dto);
  }

  // ==================== User Profile ====================

  @Put('profile')
  @ValidUser()
  @ApiBearerAuth('JWT-auth')
  @ApiBearerAuth('refresh-token')
  @ApiOperation({ summary: 'Update user profile' })
  updateProfile(@Body() dto: UpdateProfileDto, @Req() req: any) {
    return this.authService.updateProfile(req.user.id, dto);
  }

  // ==================== Discord OAuth ====================

  @Get('discord-auth-url')
  @ApiOperation({
    summary: 'Get Discord OAuth Authorization URL',
    description:
      'Returns the Discord OAuth URL for manual redirect from frontend. Useful for testing and custom implementations.',
  })
  getDiscordAuthUrl() {
    const clientId = this.configService.get<string>('DISCORD_CLIENT_ID');
    const redirectUri =
      this.configService.get<string>('DISCORD_CALLBACK_URL') ||
      'http://localhost:6545/auth/discord/callback';
    const scope = 'identify email';

    const discordAuthUrl = `https://discord.com/api/oauth2/authorize?client_id=${clientId}&redirect_uri=${encodeURIComponent(redirectUri)}&response_type=code&scope=${encodeURIComponent(scope)}`;

    return {
      success: true,
      message: 'Discord OAuth URL generated successfully',
      url: discordAuthUrl,
      instructions: [
        '1. Copy the URL',
        '2. Open in browser or redirect from frontend using: window.location.href = url',
        '3. User logs in and authorizes',
        '4. Browser redirects to callback URL with authorization code',
        '5. Backend exchanges code for tokens and redirects to frontend',
      ],
    };
  }

  @Get('discord')
  @UseGuards(AuthGuard('discord'))
  @ApiOperation({
    summary: 'Initiate Discord OAuth login',
    description:
      'Redirects user to Discord for authentication (Passport handles redirect)',
  })
  async discordLogin() {
    // Guard redirects to Discord
  }

  @Get('discord/callback')
  @UseGuards(AuthGuard('discord'))
  @ApiOperation({
    summary: 'Discord OAuth callback',
    description: 'Discord redirects back here after user authenticates',
  })
  async discordCallback(@Req() req: any, @Res() res: any) {
    try {
      const discordUser = req.user;

      const result = await this.authService.discordAuthCallback(discordUser);

      const isProduction = process.env.NODE_ENV === 'production';
      const accessTokenConfigMs = Number(
        this.configService.get('ACCESS_TOKEN_EXPIRATION_MS'),
      );
      const refreshTokenConfigMs = Number(
        this.configService.get('REFRESH_TOKEN_EXPIRATION_MS'),
      );
      const accessTokenExpirMs = Math.floor(
        isNaN(accessTokenConfigMs) ? 15 * 60 * 1000 : accessTokenConfigMs,
      );
      const refreshTokenExpirMs = Math.floor(
        isNaN(refreshTokenConfigMs)
          ? 7 * 24 * 60 * 60 * 1000
          : refreshTokenConfigMs,
      );

      // Set cookies
      res.cookie('access_token', result.access_token, {
        httpOnly: false,
        secure: isProduction,
        sameSite: 'lax',
        maxAge: accessTokenExpirMs,
      });

      res.cookie('refresh_token', result.refresh_token, {
        httpOnly: false,
        secure: isProduction,
        sameSite: 'lax',
        maxAge: refreshTokenExpirMs,
      });

      // Redirect to frontend with tokens in query params or return HTML with JS to set tokens
      const frontendUrl =
        this.configService.get<string>('FRONTEND_URL') ||
        'http://localhost:3000'; //
      const redirectUrl = `${frontendUrl}?access_token=${result.access_token}&refresh_token=${result.refresh_token}&user=${encodeURIComponent(JSON.stringify(result.user))}`;

      return res.redirect(redirectUrl);
    } catch (error) {
      console.error('Discord callback error:', error);
      return res.redirect(
        `${this.configService.get<string>('FRONTEND_URL') || 'http://localhost:3000'}?error=discord_auth_failed`,
      );
    }
  }

  // ==================== Security ====================

  @Get('sessions')
  @ValidUser()
  @ApiBearerAuth('JWT-auth')
  @ApiBearerAuth('refresh-token')
  @ApiOperation({ summary: 'View active sessions' })
  getSessions(@Req() req: any) {
    return this.authService.getSessions(req.user.id);
  }

  @Delete('logout-all')
  @ValidAdmin()
  @ApiBearerAuth('JWT-auth')
  @ApiBearerAuth('refresh-token')
  @ApiOperation({ summary: 'Logout from all devices (admin only)' })
  logoutAll(@Req() req: any) {
    return this.authService.logoutAll(req.user.id);
  }
}
