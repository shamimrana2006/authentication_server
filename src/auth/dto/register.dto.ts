import { ApiProperty } from '@nestjs/swagger';
import { Transform } from 'class-transformer';

import {
  IsEmail,
  IsLowercase,
  IsNotEmpty,
  IsOptional,
  IsString,
  IsUrl,
  MinLength,
} from 'class-validator';

export class registerDto {
  @ApiProperty({ example: 'John Doe', description: 'Name of the user' })
  @IsNotEmpty()
  @IsString({ message: 'Name must be a string.' })
  @MinLength(2, {
    message: 'Name is too short. Minimum length is $constraint1 characters.',
  })
  name: string;

  @ApiProperty({
    example: 'john.doe@example.com',
    description: 'Email address of the user',
  })
  @IsNotEmpty({ message: 'Email is required.' })
  @IsEmail()
  email: string;

  @ApiProperty({
    example: 'strongPassword123',
    description: 'Password for the user account',
    required: true,
  })
  @IsNotEmpty()
  @IsString({ message: 'Password must be a string.' })
  @MinLength(6, {
    message:
      'Password is too short. Minimum length is $constraint1 characters.',
  })
  password: string;

  @ApiProperty({
    example: 'johndoe',
    description: 'Username for the user account (optional) unique identifier',
    required: false,
  })
  @Transform(({ value }) => (value ? value.trim() : value))
  @IsLowercase()
  @IsOptional()
  @IsString({ message: 'Username must be a string.' })
  username?: string;

  @ApiProperty({
    example:
      'https://t3.ftcdn.net/jpg/11/61/33/36/360_F_1161333642_i694dqMuUwQEpEPdQOhuxdRC9WHPREFJ.jpg',
    description: 'URL of the user avatar (optional)',
    required: false,
  })
  @IsOptional()
  @IsUrl({}, { message: 'Avatar must be a valid URL.' })
  avatar?: string;
}
