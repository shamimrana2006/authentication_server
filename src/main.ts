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

  // Enable CORS with credentials for cookie support
  app.enableCors({
    origin: true, // Allow all origins in development
    credentials: true, // Allow cookies
    exposedHeaders: [
      'X-New-Access-Token',
      'X-New-Refresh-Token',
      'X-Access-Token',
      'X-Refresh-Token',
    ], // Expose custom headers
  });

  // Enable cookie parser
  app.use(cookieParser());

  app.useGlobalFilters(new AllExceptionFilter());
  // Enable global validation pipe
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
    .setDescription(
      'Authentication and User Management API'
    )
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

  // Setup Swagger with custom options and inline script for auto-authorization
  SwaggerModule.setup('api-docs', app, documentFactory, {
    swaggerOptions: {
      persistAuthorization: true,
      withCredentials: true, 
    },
    // customJsStr: `
    //   console.log('%c🔧 Swagger Auto-Auth Loading...', 'color: #00ff00; font-weight: bold;');
      
    //   function getCookie(name) {
    //     const value = \`; \${document.cookie}\`;
    //     const parts = value.split(\`; \${name}=\`);
    //     if (parts.length === 2) return parts.pop().split(';').shift();
    //     return null;
    //   }
      
    //   function deleteCookie(name) {
    //     document.cookie = name + '=; expires=Thu, 01 Jan 1970 00:00:00 UTC; path=/;';
    //   }
      
    //   function autoAuthorizeSwagger() {
    //     const accessToken = getCookie('access_token');
    //     const refreshToken = getCookie('refresh_token');
        
    //     if (!accessToken && !refreshToken) return false;
        
    //     const checkSwaggerUI = setInterval(() => {
    //       if (window.ui && window.ui.authActions) {
    //         clearInterval(checkSwaggerUI);
            
    //         console.log('%c🎉 AUTO-AUTHORIZING SWAGGER...', 'color: #00ff00; font-size: 16px; font-weight: bold;');
            
    //         try {
    //           const authObj = {};
              
    //           if (accessToken) {
    //             authObj['JWT-auth'] = {
    //               name: 'JWT-auth',
    //               schema: { type: 'http', scheme: 'bearer', in: 'header' },
    //               value: accessToken
    //             };
    //             console.log('%c✅ Access Token Set', 'color: #00ff00;');
    //           }
              
    //           if (refreshToken) {
    //             authObj['refresh-token'] = {
    //               name: 'refresh-token',
    //               schema: { type: 'apiKey', in: 'header', name: 'x-refresh-token' },
    //               value: refreshToken
    //             };
    //             console.log('%c✅ Refresh Token Set', 'color: #00ff00;');
    //           }
              
    //           window.ui.authActions.authorize(authObj);
              
    //           console.log('%c🔒 Authorize button is now LOCKED!', 'color: #00ff00; font-weight: bold;');
              
    //           // Add logout button functionality
    //           setupLogoutListener();
    //         } catch (error) {
    //           console.error('Auto-auth failed:', error);
    //         }
    //       }
    //     }, 100);
        
    //     setTimeout(() => clearInterval(checkSwaggerUI), 10000);
    //   }
      
    //   function setupLogoutListener() {
    //     // Listen for logout clicks to clear cookies
    //     document.addEventListener('click', function(e) {
    //       const target = e.target;
    //       if (target && (target.textContent === 'Logout' || target.classList.contains('btn-done'))) {
    //         setTimeout(() => {
    //           console.log('%c🚪 Logout detected - Clearing cookies...', 'color: #ff9900; font-weight: bold;');
    //           deleteCookie('access_token');
    //           deleteCookie('refresh_token');
    //           console.log('%c✅ Cookies cleared! Button is now unlocked.', 'color: #00ff00;');
    //         }, 100);
    //       }
    //     }, true);
    //   }
      
    //   window.clearSwaggerAuth = function() {
    //     if (window.ui && window.ui.authActions) {
    //       window.ui.authActions.logout(['JWT-auth', 'refresh-token']);
    //       deleteCookie('access_token');
    //       deleteCookie('refresh_token');
    //       console.log('%c✅ Authorization and cookies cleared!', 'color: #00ff00; font-weight: bold;');
    //     }
    //   };
      
    //   setTimeout(autoAuthorizeSwagger, 1500);
      
    //   const originalFetch = window.fetch;
    //   window.fetch = function(...args) {
    //     return originalFetch.apply(this, args).then(response => {
    //       const url = args[0];
          
    //       // Check for token refresh headers in ANY response
    //       const newAccessToken = response.headers.get('X-New-Access-Token');
    //       const newRefreshToken = response.headers.get('X-New-Refresh-Token');
          
    //       if (newAccessToken || newRefreshToken) {
    //         console.log('%c🔄 NEW TOKENS DETECTED!', 'color: #ffff00; font-weight: bold; font-size: 14px;');
    //         console.log('%c   Access Token:', 'color: #00ff00;', newAccessToken ? '✅ Updated' : '⏭️ Unchanged');
    //         console.log('%c   Refresh Token:', 'color: #00ff00;', newRefreshToken ? '✅ Updated' : '⏭️ Unchanged');
            
    //         // Re-authorize Swagger with new tokens
    //         setTimeout(() => {
    //           autoAuthorizeSwagger();
    //           console.log('%c🎉 Swagger authorization updated with new tokens!', 'color: #00ff00; font-weight: bold;');
    //         }, 500);
    //       }
          
    //       // Handle login/refresh token endpoints
    //       if (typeof url === 'string' && (url.includes('/auth/login') || url.includes('/auth/refresh-token'))) {
    //         setTimeout(() => {
    //           if (getCookie('access_token')) {
    //             console.log('%c🔄 Re-authorizing after login...', 'color: #00ff00;');
    //             autoAuthorizeSwagger();
    //           }
    //         }, 1000);
    //       }
          
    //       // Clear auth on logout endpoint
    //       if (typeof url === 'string' && url.includes('/auth/logout')) {
    //         setTimeout(() => {
    //           deleteCookie('access_token');
    //           deleteCookie('refresh_token');
    //           if (window.ui && window.ui.authActions) {
    //             window.ui.authActions.logout(['JWT-auth', 'refresh-token']);
    //           }
    //           console.log('%c✅ Logged out - Cookies and auth cleared!', 'color: #00ff00;');
    //         }, 500);
    //       }
          
    //       return response;
    //     });
    //   };
      
    //   window.reauthorizeSwagger = autoAuthorizeSwagger;
    //   console.log('%c💡 Commands: reauthorizeSwagger() | clearSwaggerAuth()', 'color: #00aaff;');
    // `,
  });

  await app.listen(port);
  // console.log(`server running at http://localhost:${port}`);
  console.log(`API docs available at http://localhost:${port}/api-docs`);
}
bootstrap();
