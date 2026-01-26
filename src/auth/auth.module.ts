import { Module } from '@nestjs/common';
import { AuthService } from './auth.service';
import { AuthController } from './auth.controller'; 
import { UserModule } from '../user/user.module';
import { JwtModule } from '@nestjs/jwt';
import { ConfigModule, ConfigService } from '@nestjs/config';
import { LocalStrategy } from '@/lib/strategy/local.strategy';
import { JwtStrategy } from '@/lib/strategy/jwt';
import { DiscordStrategy } from '@/lib/strategy/discord.strategy';
import { EmailModule } from '../email/email.module';
import { PassportModule } from '@nestjs/passport';
import { FirebaseAuthService } from './services/firebase-auth.service';

@Module({
  imports: [
    UserModule,
    EmailModule,
    PassportModule,
    JwtModule.registerAsync({
      imports: [ConfigModule],
      inject: [ConfigService],
      useFactory: (config: ConfigService) => ({
        secret: config.get<string>('JWT_SECRET') || 'secretKey',
        signOptions: { expiresIn: '1h' },
      }),
    }),
  ],
  controllers: [AuthController],
  providers: [
    AuthService,
    LocalStrategy,
    JwtStrategy,
    DiscordStrategy,
    FirebaseAuthService,
  ],
  exports: [AuthService, JwtModule, FirebaseAuthService],
})
export class AuthModule {}