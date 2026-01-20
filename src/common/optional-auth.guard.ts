import {
  Injectable,
  ExecutionContext,
  Inject,
  forwardRef,
  UnauthorizedException,
} from '@nestjs/common';
import { AuthGuard } from '@nestjs/passport';
import { AuthService } from '../auth/auth.service';
import { JwtService } from '@nestjs/jwt';

@Injectable()
export class OptionalJwtGuard extends AuthGuard('jwt') {
  constructor(
    @Inject(forwardRef(() => AuthService))
    private authService: AuthService,
    private jwtService: JwtService,
  ) {
    super();
  }

  async canActivate(context: ExecutionContext): Promise<boolean> {
    const request = context.switchToHttp().getRequest();
    const response = context.switchToHttp().getResponse();

    // Extract tokens from headers or cookies
    const refreshToken =
      request.headers['x-refresh-token'] || request.cookies?.refresh_token;

    let accessTokenValid = false;
    let refreshTokenValid = false;
    let decodedAccessToken = null;

    // Step 1: Check Access Token validity
    try {
      await super.canActivate(context);
      if (request.user) {
        accessTokenValid = true;
        decodedAccessToken = request.user;
      }
    } catch (err) {
      // Access token is invalid or expired
      accessTokenValid = false;
    }

    // Step 2: Check Refresh Token validity
    if (refreshToken) {
      try {
        const decoded = this.jwtService.verify(refreshToken);
        if (decoded && decoded.id) {
          const isValid = await this.authService.validateRefreshToken(
            decoded.id,
            refreshToken,
          );
          refreshTokenValid = isValid;
        }
      } catch (err) {
        // Refresh token is invalid or expired
        refreshTokenValid = false;
      }
    }

    // Step 3: Handle different scenarios
    // Scenario 1: Both tokens invalid → Logout (clear user)
    if (!accessTokenValid && !refreshTokenValid) {
      request.user = null;
      // Clear cookies to force logout
      if (response.clearCookie) {
        response.clearCookie('access_token');
        response.clearCookie('refresh_token');
      }
      return true; // Optional guard, allow request but user will be null
    }

    // Scenario 2: Access token invalid, Refresh token valid → Generate new access token
    if (!accessTokenValid && refreshTokenValid) {
      try {
        const result = await this.authService.refreshToken(refreshToken);
        if (result && result.user) {
          request.user = result.user;
          this.attachTokens(response, {
            access_token: result.access_token,
            refresh_token: result.refresh_token,
          });
          return true;
        }
      } catch (err) {
        // Failed to refresh, clear user
        request.user = null;
        return true;
      }
    }

    // Scenario 3: Access token valid, Refresh token invalid → Generate new refresh token
    if (accessTokenValid && !refreshTokenValid) {
      try {
        const tokens =
          await this.authService.generateTokens(decodedAccessToken);
        this.attachTokens(response, tokens);
        return true;
      } catch (err) {
        // Failed to generate new tokens, but access is still valid
        return true;
      }
    }

    // Scenario 4: Both tokens valid → Everything is fine
    if (accessTokenValid && refreshTokenValid) {
      return true;
    }

    return true; // Return true as it's an optional guard
  }

  private attachTokens(response: any, tokens: any) {
    const isProduction = process.env.NODE_ENV === 'production';

    // Send in headers for App and Web
    response.setHeader('X-New-Access-Token', tokens.access_token);
    response.setHeader('X-New-Refresh-Token', tokens.refresh_token);

    // Update cookies
    if (response.cookie) {
      response.cookie('access_token', tokens.access_token, {
        httpOnly: false, // Allow JS access in dev for Swagger
        secure: isProduction,
        sameSite: 'lax',
        maxAge: 15 * 60 * 1000, // 15 minutes
      });
      response.cookie('refresh_token', tokens.refresh_token, {
        httpOnly: false, // Allow JS access in dev for Swagger
        secure: isProduction,
        sameSite: 'lax',
        maxAge: 7 * 24 * 60 * 60 * 1000, // 7 days
      });
    }
  }

  handleRequest(err: any, user: any) {
    // Don't throw errors in optional guard
    if (err || !user) {
      return null;
    }
    return user;
  }
}
