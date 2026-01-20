import {
  ExceptionFilter,
  Catch,
  ArgumentsHost,
  HttpException,
  HttpStatus,
} from '@nestjs/common';
import { Request, Response } from 'express';
import { Prisma } from 'generated/client';

@Catch()
export class AllExceptionFilter implements ExceptionFilter {
  catch(exception: unknown, host: ArgumentsHost) {
    const ctx = host.switchToHttp();
    const response = ctx.getResponse<Response>();
    const request = ctx.getRequest<Request>();

    let status = HttpStatus.INTERNAL_SERVER_ERROR;
    let message: any = 'Internal server error';

    /* ===============================
        1️⃣ NestJS HttpException
    ================================ */
    if (exception instanceof HttpException) {
      status = exception.getStatus();
      const res = exception.getResponse();

      message = typeof res === 'string' ? res : (res as any).message || res;
    } else if (exception instanceof Prisma.PrismaClientKnownRequestError) {
      /* ===============================
        2️⃣ Prisma Known Errors
    ================================ */
      switch (exception.code) {
        case 'P2002':
          status = HttpStatus.CONFLICT;
          message = `Duplicate value for: ${exception.meta?.target}`;
          break;

        case 'P2025':
          status = HttpStatus.NOT_FOUND;
          message = 'Record not found';
          break;

        case 'P2003':
          status = HttpStatus.BAD_REQUEST;
          message = 'Foreign key constraint failed';
          break;

        default:
          status = HttpStatus.BAD_REQUEST;
          message = exception.message;
      }
    } else if (exception instanceof Prisma.PrismaClientValidationError) {
      /* ===============================
        3️⃣ Prisma Validation Error
    ================================ */
      status = HttpStatus.BAD_REQUEST;
      message = 'Invalid prisma query data';
    } else if (exception instanceof Error) {
      /* ===============================
        4️⃣ Normal JS Error
    ================================ */
      message = exception.message;
    }

    response.status(status).json({
      success: false,
      statusCode: status,
      timestamp: new Date().toISOString(),
      path: request.url,
      message,
    });
  }
}
