import { ApiProperty } from '@nestjs/swagger';
import { Transform } from 'class-transformer';
import { IsNotEmpty, IsString } from 'class-validator';

export class loginDto {
  @ApiProperty({
    example: 'john.doe@example.com',
    description: 'Email address of the user',
  })
  @IsNotEmpty({ message: 'Email or Username is required.' })
  @IsString({ message: 'Email or Username must be a string.' })
  emailOrUsername: string;
  
  @ApiProperty({
    example: 'strongPassword123',
    description: 'Password for the user account',
  })
  @IsNotEmpty({ message: 'Password is required.' })
  password: string;
}
