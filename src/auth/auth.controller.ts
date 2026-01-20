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
import { OptionalJwtGuard } from '@/common/optional-auth.guard';

@ApiTags('auth')
@Controller('auth')
export class AuthController {
  constructor(private readonly authService: AuthService) {}

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

    // Set cookies for automatic token management
    res.cookie('access_token', result.access_token, {
      httpOnly: false, // Allow JavaScript access in dev for Swagger
      secure: isProduction,
      sameSite: 'lax',
      maxAge: 15 * 60 * 1000, // 15 minutes
    });

    res.cookie('refresh_token', result.refresh_token, {
      httpOnly: false, // Allow JavaScript access in dev for Swagger
      secure: isProduction,
      sameSite: 'lax',
      maxAge: 7 * 24 * 60 * 60 * 1000, // 7 days
    });

    // Also send tokens in response headers for easy copy-paste in Swagger
    res.setHeader('X-Access-Token', result.access_token);
    res.setHeader('X-Refresh-Token', result.refresh_token);

    return result;
  }

  @Get('me')
  @UseGuards(OptionalJwtGuard)
  @ApiBearerAuth('JWT-auth')
  @ApiBearerAuth('refresh-token')
  @ApiOperation({
    summary: 'Get current user profile (supports auto token refresh)',
  })
  async getMe(@Req() req: any, @Res({ passthrough: true }) res: any) {
    if (!req.user) {
      return {
        success: false,
        message: 'Not authenticated - both tokens invalid',
        user: null,
      };
    }
    const user = await this.authService.getMe(req.user.id);

    // Check if new tokens were issued (they'll be in response headers)
    const newAccessToken = res.getHeader('X-New-Access-Token');
    const newRefreshToken = res.getHeader('X-New-Refresh-Token');

    return {
      success: true,
      user,
      tokensRefreshed: !!(newAccessToken && newRefreshToken),
    };
  }

  @Post('logout')
  @UseGuards(AuthGuard('jwt'))
  @ApiBearerAuth('JWT-auth')
  @ApiOperation({ summary: 'Logout from current device (clears cookies)' })
  async logout(
    @Body() body: RefreshTokenDto,
    @Req() req: any,
    @Res({ passthrough: true }) res: any,
  ) {
    const result = await this.authService.logout(
      req.user.id,
      body.refreshToken,
    );

    // Clear cookies on logout
    res.clearCookie('access_token');
    res.clearCookie('refresh_token');

    return result;
  }

  @Post('refresh-token')
  @ApiOperation({
    summary:
      'Refresh access token using refresh token (updates cookies + headers)',
  })
  async refreshToken(
    @Body() body: RefreshTokenDto,
    @Res({ passthrough: true }) res: any,
  ) {
    const result = await this.authService.refreshToken(body.refreshToken);

    const isProduction = process.env.NODE_ENV === 'production';

    // Update cookies with new tokens
    res.cookie('access_token', result.access_token, {
      httpOnly: false,
      secure: isProduction,
      sameSite: 'lax',
      maxAge: 15 * 60 * 1000, // 15 minutes
    });

    res.cookie('refresh_token', result.refresh_token, {
      httpOnly: false,
      secure: isProduction,
      sameSite: 'lax',
      maxAge: 7 * 24 * 60 * 60 * 1000, // 7 days
    });

    // Send in headers too
    res.setHeader('X-Access-Token', result.access_token);
    res.setHeader('X-Refresh-Token', result.refresh_token);

    return result;
  }

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

  @Post('resend-reset-otp')
  @ApiOperation({ summary: 'Resend password reset OTP' })
  resendResetOtp(@Body() dto: ResendOtpDto) {
    return this.authService.resendResetOtp(dto);
  }

  @Put('change-password')
  @UseGuards(AuthGuard('jwt'))
  @ApiBearerAuth('JWT-auth')
  @ApiOperation({ summary: 'Change password when logged in' })
  changePassword(@Body() dto: ChangePasswordDto, @Req() req: any) {
    return this.authService.changePassword(req.user.id, dto);
  }

  // ==================== Username Management ====================

  @Post('check-username')
  @UseGuards(OptionalJwtGuard)
  @ApiBearerAuth('JWT-auth')
  @ApiBearerAuth('refresh-token')
  @ApiOperation({ summary: 'Check if username is available (optional auth)' })
  checkUsername(@Body() dto: CheckUsernameDto, @Req() req: any) {
    return this.authService.checkUsername(dto, req.user?.id);
  }

  @Put('update-username')
  @UseGuards(AuthGuard('jwt'))
  @ApiBearerAuth('JWT-auth')
  @ApiOperation({ summary: 'Update username' })
  updateUsername(@Body() dto: UpdateUsernameDto, @Req() req: any) {
    return this.authService.updateUsername(req.user.id, dto);
  }

  // @Post('forgot-username')
  // @ApiOperation({ summary: 'Send username to email' })
  // forgotUsername(@Body() body: { email: string }) {
  //   return this.authService.forgotUsername(body.email);
  // }

  // ==================== User Profile ====================

  @Put('profile')
  @UseGuards(AuthGuard('jwt'))
  @ApiBearerAuth('JWT-auth')
  @ApiOperation({ summary: 'Update user profile' })
  updateProfile(@Body() dto: UpdateProfileDto, @Req() req: any) {
    return this.authService.updateProfile(req.user.id, dto);
  }

  // ==================== Security ====================

  @Get('sessions')
  @UseGuards(AuthGuard('jwt'))
  @ApiBearerAuth('JWT-auth')
  @ApiOperation({ summary: 'View active sessions' })
  getSessions(@Req() req: any) {
    return this.authService.getSessions(req.user.id);
  }

  @Delete('logout-all')
  @UseGuards(AuthGuard('jwt'))
  @ApiBearerAuth('JWT-auth')
  @ApiOperation({ summary: 'Logout from all devices' })
  logoutAll(@Req() req: any) {
    return this.authService.logoutAll(req.user.id);
  }
}
