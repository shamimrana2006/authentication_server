import { Injectable } from '@nestjs/common';
import { PassportStrategy } from '@nestjs/passport';
import { Strategy } from 'passport-discord';
import { ConfigService } from '@nestjs/config';
 
@Injectable()
export class DiscordStrategy extends PassportStrategy(Strategy, 'discord') {
  constructor(private configService: ConfigService) {
    super({
      clientID: configService.get<string>('DISCORD_CLIENT_ID'),
      clientSecret: configService.get<string>('DISCORD_CLIENT_SECRET'),
      callbackURL: configService.get<string>('DISCORD_CALLBACK_URL'),
      scope: ['identify', 'email'],
    } as any);
  }

  async validate(
    accessToken: string,
    refreshToken: string,
    profile: any,
    done: Function,
  ) {
    const { id, username, email, avatar, discriminator } = profile;

    const user = {
      discordId: id,
      username: username,
      email: email,
      name: username,
      avatar: avatar
        ? `https://cdn.discordapp.com/avatars/${id}/${avatar}.png`
        : `https://i.pinimg.com/236x/1a/a8/d7/1aa8d75f3498784bcd2617b3e3d1e0c4.jpg`,
      provider: 'discord',
    };

    return done(null, user);
  }
}
