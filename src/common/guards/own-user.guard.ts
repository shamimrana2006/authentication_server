import {
  Injectable,
  CanActivate,
  ExecutionContext,
  ForbiddenException,
} from '@nestjs/common';

@Injectable()
export class OwnUserGuard implements CanActivate {
  canActivate(context: ExecutionContext): boolean {
    const request = context.switchToHttp().getRequest();
    const user = request.user;
    const userId = request.params.id || request.params.userId;
    
    if (user.id === userId) {
      return true;
    }
    throw new ForbiddenException('Access denied');
  }
}