import { NestFactory } from '@nestjs/core';
import { AppModule } from './app.module';
import 'dotenv/config';
import { SwaggerModule, DocumentBuilder } from '@nestjs/swagger';
import { ValidationPipe } from '@nestjs/common';
import { AllExceptionFilter } from './common/all-exception.filter';
import cookieParser from 'cookie-parser';
import { join } from 'path';
import { NestExpressApplication } from '@nestjs/platform-express';

async function bootstrap() {
  const app = await NestFactory.create<NestExpressApplication>(AppModule);
  const port = process.env.PORT ?? 3000;

  const hasValue = (value?: string) =>
    !!value &&
    value.trim() !== '' &&
    !['undefined', 'null'].includes(value.trim().toLowerCase());
  const isTruthyEnv = (value?: string) =>
    ['true', '1', 'yes', 'on'].includes((value ?? '').toLowerCase());

  // Serve public folder for swagger-helper.js
  app.useStaticAssets(join(__dirname, '..', 'public'));

  app.useStaticAssets(join(__dirname, 'auth'), {
    prefix: '/auth',
  });

  // Enable CORS with credentials for cookie support
  app.enableCors({
    origin: true,
    credentials: true,
    exposedHeaders: [
      'X-New-Access-Token',
      'X-New-Refresh-Token',
      'X-Access-Token',
      'X-Refresh-Token',
    ],
  });

  app.use(cookieParser());

  app.useGlobalFilters(new AllExceptionFilter());

  app.useGlobalPipes(
    new ValidationPipe({
      whitelist: true,
      forbidNonWhitelisted: true,
      transform: true,
      transformOptions: {
        enableImplicitConversion: true,
      },
    }),
  );

  const config = new DocumentBuilder()
   .setTitle(`${process.env.SERVER_NAME} API`)
    .setDescription(`${process.env.SERVER_NAME} Authentication and User Management API`)
    .setVersion('1.0')
    .addTag('auth', 'Authentication endpoints')
    .addTag('uploads', 'File upload endpoints')
    .addBearerAuth(
      {
        type: 'http',
        scheme: 'bearer',
        bearerFormat: 'JWT',
        name: 'Authorization',
        description:
          'Enter JWT Access Token (get from login response or browser console)',
        in: 'header',
      },
      'JWT-auth',
    )
    .addApiKey(
      {
        type: 'apiKey',
        name: 'x-refresh-token',
        in: 'header',
        description:
          'Enter Refresh Token (get from login response or browser console)',
      },
      'refresh-token',
    )
    .build();
  const documentFactory = () => {
    const document = SwaggerModule.createDocument(app, config);

    const hasDiscordCreds = [
      'DISCORD_CLIENT_ID',
      'DISCORD_CLIENT_SECRET',
      'DISCORD_CALLBACK_URL',
    ].every((key) => hasValue(process.env[key]));
    if (!hasDiscordCreds) {
      [
        '/auth/discord-auth-url',
        '/auth/discord',
        '/auth/discord/callback',
      ].forEach((path) => {
        delete document.paths[path as keyof typeof document.paths];
      });
    }

    const hasFirebaseCreds = [
      'FIREBASE_PROJECT_ID',
      'FIREBASE_PRIVATE_KEY',
      'FIREBASE_CLIENT_EMAIL',
    ].every((key) => hasValue(process.env[key]));

    if (!hasFirebaseCreds) {
      delete document.paths['/auth/firebase-login'];
    } else {
      const providerFlags = [
        ['google', 'Google'],
        ['facebook', 'Facebook'],
        ['github', 'GitHub'],
        ['apple', 'Apple'],
        ['twitter', 'Twitter'],
      ].filter(([envKey]) => isTruthyEnv(process.env[envKey]));

      const providerSummary = providerFlags.length
        ? `Enabled providers: ${providerFlags.map(([, label]) => label).join(', ')}`
        : 'No provider flags enabled';

      const firebasePath = document.paths['/auth/firebase-login'] as any;
      if (firebasePath?.post) {
        firebasePath.post.summary = `Firebase Social Login/Register - ${providerSummary}`;
        firebasePath.post.description = `${firebasePath.post.description || 'Universal social login endpoint using Firebase Authentication.'} ${providerSummary}`;
      }
    }

    return document;
  };

  SwaggerModule.setup('api-docs', app, documentFactory, {
    swaggerOptions: {
      persistAuthorization: true,
      withCredentials: true,
    },
    customJs: '/swagger-helper.js',
  });
  await app.listen(port);
  console.log(`API docs available at http://localhost:${port}/api-docs`);
}
bootstrap();
