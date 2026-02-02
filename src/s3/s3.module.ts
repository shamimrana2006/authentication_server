import { Module } from '@nestjs/common';
import { ConfigModule } from '@nestjs/config';
import { AwsModule } from '../aws/aws.module';
import { S3Controller } from './s3.controller';

@Module({
  imports: [ConfigModule, AwsModule],
  controllers: [S3Controller],
})
export class S3Module {}
