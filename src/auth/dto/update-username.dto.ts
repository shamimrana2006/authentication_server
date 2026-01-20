import { ApiProperty } from '@nestjs/swagger';
import { IsNotEmpty, IsString, MinLength } from 'class-validator';

export class UpdateUsernameDto {
  @ApiProperty({ example: 'newusername' })
  @IsNotEmpty()
  @IsString()
  @MinLength(3)
  username: string;
}
