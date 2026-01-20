import {
  IsEmail,
  IsString,
  IsOptional,
  MinLength,
  MaxLength,
  IsBoolean,
  IsUrl,
} from 'class-validator';
import { ApiProperty, ApiPropertyOptional } from '@nestjs/swagger';
import { Transform } from 'class-transformer';

export class CreateUserDto {
  @ApiProperty({
    example: 'user@example.com',
    description: 'User email address',
  })
  @IsEmail({}, { message: 'Please provide a valid email address' })
  email: string;

  @ApiPropertyOptional({ example: 'johndoe', description: 'Unique username' })
  @IsOptional()
  @IsString()
  @MinLength(3, { message: 'Username must be at least 3 characters long' })
  @MaxLength(20, { message: 'Username must not exceed 20 characters' })
  @Transform(({ value }) => value?.trim())
  username?: string;

  @ApiPropertyOptional({
    example: 'P@ssw0rd123',
    description: 'User password (hashed)',
  })
  @IsOptional()
  @IsString()
  @MinLength(8, { message: 'Password must be at least 8 characters long' })
  password?: string;

  @ApiPropertyOptional({ example: 'John Doe', description: 'Full name' })
  @IsOptional()
  @IsString()
  name?: string;

  @ApiPropertyOptional({
    example: 'https://example.com/avatar.jpg',
    description: 'Avatar URL',
  })
  @IsOptional()
  @IsUrl(
    {},
    {
      message:
        'Please provide a valid URL for the avatar like : https://example.com/avatar.jpg',
    },
  )
  avatar?: string;

  @ApiPropertyOptional({
    example: false,
    description: 'Email verification status',
  })
  @IsOptional()
  @IsBoolean()
  emailVerified?: boolean;

  @ApiPropertyOptional({ description: 'Google OAuth ID' })
  @IsOptional()
  @IsString()
  googleId?: string;

  @ApiPropertyOptional({ description: 'GitHub OAuth ID' })
  @IsOptional()
  @IsString()
  githubId?: string;

  @ApiPropertyOptional({ description: 'Discord OAuth ID' })
  @IsOptional()
  @IsString()
  discord?: string;
}
