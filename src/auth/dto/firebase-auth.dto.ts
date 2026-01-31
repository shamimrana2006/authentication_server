import { ApiProperty } from '@nestjs/swagger';
import { IsNotEmpty, IsString } from 'class-validator';

export class FirebaseAuthDto {
  @ApiProperty({
    example:
      'eyJhbGciOiJSUzI1NiIsImtpZCI6IjEifQ.eyJpc3MiOiJodHRwczovL2FjY291bnRzLmdvb2dsZS5jb20iLCJhdWQiOiJqY29ubmVjdC1iNmY4OS5maXJlYmFzZWFwcC5jb20iLCJhdXRoX3RpbWUiOjE3MDU2Njc4OTcsInVzZXJfaWQiOiI4dDFjMjBWMjF5VUFSZXhlalowQjJQaVQxNkczIiwic3ViIjoiOHQxYzIwVjIxeVVBUkV4ZWpaMEIyUGlUMTZHMyIsImlhdCI6MTcwNTY2Nzg5NywiZXhwIjoxNzA1NjcxNDk3LCJlbWFpbCI6InRlc3RAZ21haWwuY29tIiwiZW1haWxfdmVyaWZpZWQiOnRydWUsImZpcmViYXNlIjp7ImlkZW50aXRpZXMiOnsiZ29vZ2xlLmNvbSI6W3sibWlkIjoiMTA3ODY5NDUzNDM0NzM0ODUzNDUzNDUiLCJuYW1lIjoiVGVzdCBVc2VyIiwicGljdHVyZSI6Imh0dHBzOi8vbGgzLmdvb2dsZXVzZXJjb250ZW50LmNvbS9hLS9BRGNtNXjzR3N0NzJkOGIzd3pWUy8zcGhvdG8uanBnIn1dfSwic2lnbl9pbl9wcm92aWRlciI6Imdvb2dsZS5jb20ifX0.signature',
    description:
      'Firebase ID Token from any social provider (Google, Apple, Facebook, GitHub, etc.) - obtained from Firebase Authentication on frontend',
  })
  @IsNotEmpty({ message: 'Token is required' })
  @IsString({ message: 'Token must be a string' })
  token: string;
}
