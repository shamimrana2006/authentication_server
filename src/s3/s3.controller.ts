import {
  Controller,
  Post,
  UploadedFile,
  UseInterceptors,
  BadRequestException,
} from '@nestjs/common';
import { FileInterceptor } from '@nestjs/platform-express';
import { memoryStorage } from 'multer';
import { S3Service } from './s3.service';
import {
  ApiTags,
  ApiOperation,
  ApiConsumes,
  ApiBody,
  ApiResponse,
} from '@nestjs/swagger';

@ApiTags('uploads')
@Controller('s3')
export class S3Controller {
  constructor(private readonly s3: S3Service) {}

  @Post('upload')
  @ApiOperation({ summary: 'Upload an image or file to S3' })
  @ApiConsumes('multipart/form-data')
  @ApiBody({
    schema: {
      type: 'object',
      properties: {
        file: {
          type: 'string',
          format: 'binary',
          description: 'File to upload (image or other)',
        },
      },
    },
  })
//   @ApiResponse({ status: 201, description: 'File uploaded successfully' })
  @UseInterceptors(
    FileInterceptor('file', {
      storage: memoryStorage(),
      limits: { fileSize: 10 * 1024 * 1024 },
    }),
  )
  async upload(@UploadedFile() file: Express.Multer.File) {
    if (!file) throw new BadRequestException('No file provided');

    const key = `uploads/${Date.now()}-${file.originalname}`;
    const result = await this.s3.uploadFile(file.buffer, key, file.mimetype);
    return { success: true, ...result };
  }
}
