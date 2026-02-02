import {
  Controller,
  Post,
  UploadedFile,
  UploadedFiles,
  UseInterceptors,
  BadRequestException,
} from '@nestjs/common';
import { FileInterceptor, FilesInterceptor } from '@nestjs/platform-express';
import { memoryStorage } from 'multer';
import { AwsService } from '../aws/aws.service';
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
  constructor(private readonly awsService: AwsService) {}

  @Post('upload')
  @ApiOperation({ summary: 'Upload a single file to S3' })
  @ApiConsumes('multipart/form-data')
  @ApiBody({
    schema: {
      type: 'object',
      properties: {
        file: {
          type: 'string',
          format: 'binary',
          description: 'File to upload (any type)',
        },
      },
    },
  })
  @ApiResponse({ status: 201, description: 'File uploaded successfully' })
  @ApiResponse({ status: 400, description: 'No file provided' })
  @UseInterceptors(
    FileInterceptor('file', {
      storage: memoryStorage(),
      limits: { fileSize: 10 * 1024 * 1024 }, // 10MB limit
    }),
  )
  async upload(@UploadedFile() file: Express.Multer.File) {
    if (!file) throw new BadRequestException('No file provided');

    const result = await this.awsService.upload(file);
    return result;
  }

  @Post('upload-multiple')
  @ApiOperation({
    summary: 'Upload multiple files with single choose button',
    description:
      'Click choose button once and select multiple files together. Hold Ctrl (Windows) or Cmd (Mac) to select multiple files. Maximum 20 files, 10MB each.',
  })
  @ApiConsumes('multipart/form-data')
  @ApiBody({
    schema: {
      type: 'object',
      required: ['files'],
      properties: {
        files: {
          type: 'array',
          items: {
            type: 'string',
            format: 'binary',
          },
          description: 'Select multiple files at once (Ctrl/Cmd + Click)',
        },
      },
    },
    description: 'Upload multiple files using single file chooser',
  })
  @ApiResponse({
    status: 201,
    description: 'All files uploaded successfully',
    schema: {
      type: 'object',
      properties: {
        status: { type: 'string', example: 'success' },
        message: { type: 'string', example: '5 file(s) uploaded successfully' },
        files: {
          type: 'array',
          items: {
            type: 'object',
            properties: {
              url: {
                type: 'string',
                example: 'https://bucket.s3.amazonaws.com/uploads/file.pdf',
              },
              filename: { type: 'string', example: 'document.pdf' },
              mimetype: { type: 'string', example: 'application/pdf' },
              size: { type: 'number', example: 1048576 },
            },
          },
        },
        count: { type: 'number', example: 5 },
      },
    },
  })
  @ApiResponse({
    status: 400,
    description: 'No files provided or exceeded file limit',
  })
  @UseInterceptors(
    FilesInterceptor('files', 20, {
      storage: memoryStorage(),
      limits: { fileSize: 10 * 1024 * 1024 },
    }),
  )
  async uploadMultiple(@UploadedFiles() files: Express.Multer.File[]) {
    if (!files || files.length === 0) {
      throw new BadRequestException('No files provided');
    }

    if (files.length > 20) {
      throw new BadRequestException(
        'Maximum 20 files allowed in single upload',
      );
    }

    const result = await this.awsService.uploadMultiple(files);
    return result;
  }
}
