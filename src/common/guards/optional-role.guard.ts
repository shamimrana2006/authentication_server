import {
  Injectable,
  CanActivate,
  ExecutionContext,
  ForbiddenException,
} from '@nestjs/common';
import { Reflector } from '@nestjs/core';

@Injectable()
export class OptionalRoleGuard implements CanActivate {
  constructor(private reflector: Reflector) {}

  canActivate(context: ExecutionContext): boolean {
    const requiredRoles = this.reflector.get<string[]>(
      'roles',
      context.getHandler(),
    );

    if (!requiredRoles) {
      return true; // No roles required
    }

    const request = context.switchToHttp().getRequest();
    const user = request.user;

    // If no user, allow access (truly optional)
    if (!user || !user.role) {
      return true;
    }

    // If user exists, validate role
    if (!requiredRoles.includes(user.role)) {
      throw new ForbiddenException(
        `Only ${requiredRoles.join(', ')} can access this resource`,
      );
    }

    return true;
  }
}
