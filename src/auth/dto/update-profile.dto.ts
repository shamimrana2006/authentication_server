import { ApiProperty } from '@nestjs/swagger';
import { IsOptional, IsString, IsEnum, IsDateString } from 'class-validator';

export enum GenderEnum {
  MALE = 'MALE',
  FEMALE = 'FEMALE',
  OTHER = 'OTHER',
  PREFER_NOT_TO_SAY = 'PREFER_NOT_TO_SAY',
}

export class UpdateProfileDto {
  @ApiProperty({
    example: 'John Doe',
    required: false,
    description: 'User full name',
  })
  @IsOptional()
  @IsString()
  name?: string;

  @ApiProperty({
    example: '',
    required: false,
    description: 'Unique username',
  })
  @IsOptional()
  @IsString()
  username?: string;

  @ApiProperty({
    enum: GenderEnum,
    example: 'MALE',
    required: false,
    description: 'Gender (MALE, FEMALE, OTHER, PREFER_NOT_TO_SAY)',
  })
  @IsOptional()
  @IsEnum(GenderEnum)
  gender?: GenderEnum;

  @ApiProperty({
    example: '1990-01-15',
    required: false,
    description: 'Date of birth (YYYY-MM-DD format)',
  })
  @IsOptional()
  @IsDateString()
  dateOfBirth?: string;

  @ApiProperty({
    type: 'string',
    format: 'binary',
    description:
      'Profile photo file (images only: jpeg, jpg, png, gif, webp, svg)',
    required: false,
  })
  @IsOptional()
  profilePhoto?: Express.Multer.File;

  @ApiProperty({
    type: 'string',
    format: 'binary',
    description: 'Avatar file (images only: jpeg, jpg, png, gif, webp, svg)',
    required: false,
  })
  @IsOptional()
  avatar?: Express.Multer.File;
}
