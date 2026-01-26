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

  // collcected payload from access token from jwt strategy
  async validate(payload: any) {
    console.log('validate payload', payload);
    return payload;
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

    let accessTokenValid = false;
    let refreshTokenValid = false;
    let decodedAccessToken = null;

    // Step 1: Check access Token validity
    if (accessToken) {
      try {
        const decoded = this.jwtService.verify(accessToken);
        if (decoded && decoded.id) {
         

          accessTokenValid = true;
        }
      } catch (err) {
        accessTokenValid = false;
      }
    }
    if (refreshToken) {
      try {
        const decoded = this.jwtService.verify(refreshToken);
        if (decoded && decoded.id) {

          refreshTokenValid = true;
        }
      } catch (err) { 
        refreshTokenValid = false;
      }
    }

    if (!accessTokenValid && !refreshTokenValid) {
      // Clear cookies to force logout
      if (response.clearCookie) {
        response.clearCookie('access_token');
        response.clearCookie('refresh_token');
      }
      throw new UnauthorizedException('Both tokens are invalid');
    }

    // Scenario 2: Access token invalid, Refresh token valid → Generate new access token only
    if (!accessTokenValid && refreshTokenValid) {
      try {
        const decodedRefreshToken = this.jwtService.decode(refreshToken);
        if (decodedRefreshToken && decodedRefreshToken.id) {
          const { exp, ...rest } = decodedRefreshToken as any;

          const tokenPayload = {
            id: rest.id,
            email: rest.email,
            name: rest.name,
            role: rest.role,
          };
          const newAccessToken =
            await this.authService.generateAccessTokenOnly(tokenPayload);

          const newRefreshToken =
            await this.authService.generateRefreshTokenOnly(
              tokenPayload,
              refreshToken,
            );

          if (newAccessToken) {
            request.user = tokenPayload;

            response.locals.activeAccessToken = newAccessToken;
            response.locals.activeRefreshToken = newRefreshToken;

            const isProduction = process.env.NODE_ENV === 'production';
            const accessTokenConfigMs = Number(
              this.configService.get('ACCESS_TOKEN_EXPIRATION_MS'),
            );
            const accessTokenExpirMs = Math.floor(
              isNaN(accessTokenConfigMs) ? 15 * 60 * 1000 : accessTokenConfigMs,
            );
            const refreshTokenConfigMs = Number(
              this.configService.get('REFRESH_TOKEN_EXPIRATION_MS'),
            );
            const refreshTokenExpirMs = Math.floor(
              isNaN(refreshTokenConfigMs)
                ? 7 * 24 * 60 * 60 * 1000
                : refreshTokenConfigMs,
            );

            response.setHeader('X-New-Refresh-Token', newRefreshToken);
            response.setHeader('X-New-Access-Token', newAccessToken);

            if (response.cookie) {
              response.cookie('access_token', newAccessToken, {
                httpOnly: false,
                secure: isProduction,
                sameSite: 'lax',
                maxAge: accessTokenExpirMs,
              });
              response.cookie('refresh_token', newRefreshToken, {
                httpOnly: false,
                secure: isProduction,
                sameSite: 'lax',
                maxAge: refreshTokenExpirMs,
              });
            }

            return true;
          }
        }
      } catch (err) {
        console.error(
          'Scenario 2 - Access token regeneration failed:',
          err.message,
        );
        request.user = null;
        return false;
      }
    }

    // Scenario 3: Access token valid, Refresh token invalid/expired → Regenerate only refresh token
   

    if (accessTokenValid && !refreshTokenValid) {
      try {
        // Generate only new refresh token, keep the valid access token
        const decodedAccessToken = this.jwtService.decode(accessToken);
        const tokenPayload = {
          id: decodedAccessToken.id,
          email: decodedAccessToken.email,
          name: decodedAccessToken.name,
          role: decodedAccessToken.role,
        };

        const newRefreshToken = await this.authService.generateRefreshTokenOnly(
          tokenPayload,
          refreshToken, // Pass old refresh token for cleanup
        );

        // Attach only the new refresh token (keep access token as is)
        const isProduction = process.env.NODE_ENV === 'production';
        const refreshTokenConfigMs = Number(
          this.configService.get('REFRESH_TOKEN_EXPIRATION_MS'),
        );
        const refreshTokenExpirMs = Math.floor(
          isNaN(refreshTokenConfigMs)
            ? 7 * 24 * 60 * 60 * 1000
            : refreshTokenConfigMs,
        );

        response.setHeader('X-New-Refresh-Token', newRefreshToken);

        // Attach to response locals so controllers can include it in response body
        // response.locals.activeAccessToken = accessToken;
        response.locals.activeRefreshToken = newRefreshToken;

        if (response.cookie) {
          response.cookie('refresh_token', newRefreshToken, {
            httpOnly: false,
            secure: isProduction,
            sameSite: 'lax',
            maxAge: refreshTokenExpirMs,
          });
        }
        request.user = tokenPayload;

        return true;
      } catch (err) {
        console.error(
          'Scenario 3 - Refresh token regeneration failed:',
          err.message,
        );
        // Failed to generate new refresh token, but access token is still valid
        return false;
      }
    }

    // Scenario 4: Both tokens valid → Everything is fine
    if (accessTokenValid && refreshTokenValid) {
      const decodedAccessToken = this.jwtService.decode(accessToken);
      request.user = {
        id: decodedAccessToken.id,
        email: decodedAccessToken.email,
        name: decodedAccessToken.name,
        role: decodedAccessToken.role,
      };
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
