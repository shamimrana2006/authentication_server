import { applyDecorators, ForbiddenException, UseGuards } from '@nestjs/common';
import { AuthGuard } from '@nestjs/passport';
import { RoleGuard } from '../guards/role.guard';
import { OptionalRoleGuard } from '../guards/optional-role.guard';
import { OwnUserGuard } from '../guards/own-user.guard';
import { Roles } from './roles.decorator';
import { OptionalJwtGuard } from '../optional-auth.guard';

// ==================== Authenticated Guards ====================

// Only authenticated users (no role restriction)
export const ValidAll = () => {
  return UseGuards(OptionalJwtGuard);
};

// Only authenticated users + user/admin role
export const ValidUser = () => {
  return applyDecorators(
    UseGuards(OptionalJwtGuard, RoleGuard),
    Roles('USER', 'ADMIN',"SUPERADMIN"),
  );
};

// Only authenticated users + admin role
export const ValidAdmin = () => {
  return applyDecorators(
    UseGuards(OptionalJwtGuard, RoleGuard),
    Roles('ADMIN', 'SUPERADMIN'),
  );
};

// Only authenticated users + superadmin role
export const ValidSuperAdmin = () => {
  return applyDecorators(
    UseGuards(OptionalJwtGuard, RoleGuard),
    Roles('SUPERADMIN'),
  );
};

// ==================== Optional Authentication Guards ====================

// Optional JWT (allows authenticated & unauthenticated) + optional role check
// export const ValidOptionalUser = () => {
//   return applyDecorators(
//     UseGuards(OptionalJwtGuard, OptionalRoleGuard),
//     Roles('USER', 'ADMIN',"SUPERADMIN"),
//   );
// };

// // Only authenticated users who own the resource
// export const ValidOwnUser = () => {
//   return applyDecorators(
//     UseGuards(OptionalJwtGuard, OwnUserGuard)
//   );
// };

// // Optional JWT + optional admin role check
// export const ValidOptionalAdmin = () => {
//   return applyDecorators();
// };

// // Optional JWT with no role restriction
// export const ValidOptionalAll = () => {
//   return UseGuards(OptionalJwtGuard);
// };
