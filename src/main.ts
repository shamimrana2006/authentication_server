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

  // app.useStaticAssets(join(__dirname, '..', 'public')); 

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
    .setTitle('Authentication API')
    .setDescription('Authentication and User Management API')
    .setVersion('1.0')
    .addTag('auth', 'Authentication endpoints')
    .addTag('users', 'User management endpoints')
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
  const documentFactory = () => SwaggerModule.createDocument(app, config);
  SwaggerModule.setup('api-docs', app, documentFactory, {
    swaggerOptions: {
      persistAuthorization: true,
      withCredentials: true,
    },
  });
  await app.listen(port);
  console.log(`API docs available at http://localhost:${port}/api-docs`);
}
bootstrap();
