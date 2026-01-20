import { PartialType } from '@nestjs/swagger';
import { registerDto } from './register.dto';

export class UpdateAuthDto extends PartialType(registerDto) {}
