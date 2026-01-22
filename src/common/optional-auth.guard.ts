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
import { ConfigService } from '@nestjs/config';

@Injectable()
export class OptionalJwtGuard extends AuthGuard('jwt') {
  constructor(
    @Inject(forwardRef(() => AuthService))
    private authService: AuthService,
    private jwtService: JwtService,
    private configService: ConfigService,
  ) {
    super();
  }

  async canActivate(context: ExecutionContext): Promise<any> {
    const request = context.switchToHttp().getRequest();
    const response = context.switchToHttp().getResponse();

    // Extract tokens from headers or cookies
    const refreshToken =
      request.headers['x-refresh-token'] || request.cookies?.refresh_token;
    const accessToken =
      request.headers['authorization']?.replace('Bearer ', '') ||
      request.cookies?.access_token;

    console.log('tokens', accessToken);
    console.log('tokens', refreshToken);

    let accessTokenValid = false;
    let refreshTokenValid = false;
    let decodedAccessToken = null;

    // Step 1: Check access Token validity
    if (accessToken) {
      try {
        const decoded = this.jwtService.verify(accessToken);
        if (decoded && decoded.id) {
          const isValid = await this.authService.validateRefreshToken(
            decoded.id,
            refreshToken,
          );
          console.log('------------------------------------------------');
          console.log('accessValid');

          accessTokenValid = isValid;
        }
      } catch (err) {
        // Access token is invalid or expired
        refreshTokenValid = false;
      }
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
          console.log('refreshvalid');
          console.log('------------------------------------------------');
          refreshTokenValid = isValid;
        }
      } catch (err) {
        // Refresh token is invalid or expired
        refreshTokenValid = false;
      }
    }

    // Step 3: Handle different scenarios
    // Scenario 1: Both tokens invalid → Logout (clear user)
    // if (!accessTokenValid && !refreshTokenValid) {
    //   request.user = null;
    //   // Clear cookies to force logout
    //   if (response.clearCookie) {
    //     response.clearCookie('access_token');
    //     response.clearCookie('refresh_token');
    //   }
    //   return true;
    // }

    // Scenario 2: Access token invalid, Refresh token valid → Generate new access token only
    if (!accessTokenValid && refreshTokenValid) {
      try {
        const decodedRefreshToken = this.jwtService.decode(refreshToken);
        if (decodedRefreshToken && decodedRefreshToken.id) {
          // Generate only new access token, keep refresh token as is
          const { exp, ...rest } = decodedRefreshToken as any;

          const newAccessToken =
            await this.authService.generateAccessTokenOnly(rest);
          if (newAccessToken) {
            request.user = decodedRefreshToken;

            // response.locals = response.locals || {};
            response.locals.newAccessToken = newAccessToken;

            const isProduction = process.env.NODE_ENV === 'production';
            const accessTokenExpirMs =
              this.configService.get<number>('ACCESS_TOKEN_EXPIRATION_MS') ||
              15 * 60 * 1000;

            response.setHeader('X-New-Access-Token', newAccessToken);

            if (response.cookie) {
              response.cookie('access_token', newAccessToken, {
                httpOnly: false,
                secure: isProduction,
                sameSite: 'lax',
                maxAge: accessTokenExpirMs,
              });
            }

            request.locals.activeAccessToken = newAccessToken;
            return true;
          }
        }
      } catch (err) {
        // Failed to regenerate access token, clear user
        console.error(
          'Scenario 2 - Access token regeneration failed:',
          err.message,
        );
        request.user = null;
        return true;
      }
    }

    // Scenario 3: Access token valid, Refresh token invalid/expired → Regenerate only refresh token
    if (accessTokenValid && !refreshTokenValid) {
      try {
        // Generate only new refresh token, keep the valid access token
        const { exp, ...rest } = decodedAccessToken as any;
        const newRefreshToken = await this.authService.generateRefreshTokenOnly(
          rest,
          refreshToken, // Pass old refresh token for cleanup
        );

        // Attach only the new refresh token (keep access token as is)
        const isProduction = process.env.NODE_ENV === 'production';
        const refreshTokenExpirMs =
          this.configService.get<number>('REFRESH_TOKEN_EXPIRATION_MS') ||
          7 * 24 * 60 * 60 * 1000;

        response.setHeader('X-New-Refresh-Token', newRefreshToken);

        // Attach to response locals so controllers can include it in response body
        response.locals.activeRefreshToken = newRefreshToken;

        if (response.cookie) {
          response.cookie('refresh_token', newRefreshToken, {
            httpOnly: false,
            secure: isProduction,
            sameSite: 'lax',
            maxAge: refreshTokenExpirMs,
          });
        }

        return true;
      } catch (err) {
        console.error(
          'Scenario 3 - Refresh token regeneration failed:',
          err.message,
        );
        // Failed to generate new refresh token, but access token is still valid
        return true;
      }
    }

    // Scenario 4: Both tokens valid → Everything is fine
    if (accessTokenValid && refreshTokenValid) {
      response.locals.activeRefreshToken = refreshToken;
      response.locals.activeAccessToken = accessToken;
      return true;
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
