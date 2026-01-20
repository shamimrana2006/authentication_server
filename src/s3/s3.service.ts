import { Injectable, InternalServerErrorException } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import {
  S3Client,
  PutObjectCommand,
  GetObjectCommand,
} from '@aws-sdk/client-s3';
import { getSignedUrl } from '@aws-sdk/s3-request-presigner';

@Injectable()
export class S3Service {
  private client: S3Client;
  private bucket: string;

  constructor(private config: ConfigService) {
    const region = this.config.get<string>('AWS_REGION');
    const accessKeyId = this.config.get<string>('AWS_ACCESS_KEY_ID');
    const secretAccessKey = this.config.get<string>('AWS_SECRET_ACCESS_KEY');
    this.bucket = this.config.get<string>('AWS_S3_BUCKET_NAME') || '';

    this.client = new S3Client({
      region,
      credentials:
        accessKeyId && secretAccessKey
          ? { accessKeyId, secretAccessKey }
          : undefined,
    });
  }

  async uploadFile(buffer: Buffer, key: string, contentType?: string) {
    if (!this.bucket)
      throw new InternalServerErrorException('S3 bucket is not configured');

    const makePublic =
      this.config.get<string>('S3_PUBLIC') === 'true' ||
      this.config.get<string>('AWS_S3_PUBLIC') === 'true';

    const params: any = {
      Bucket: this.bucket,
      Key: key,
      Body: buffer,
      ContentType: contentType || 'application/octet-stream',
    };

    if (makePublic) {
      params.ACL = 'public-read';
    }

    try {
      await this.client.send(new PutObjectCommand(params));

      // `this.client.config.region` can be a string or a provider (function returning string or Promise<string>).
      const regionConfig = this.client.config.region as any;
      let resolvedRegion: string | undefined;
      if (!regionConfig) {
        resolvedRegion = undefined;
      } else if (typeof regionConfig === 'function') {
        // Call provider and await if it returns a promise
        const maybe = regionConfig();
        resolvedRegion =
          maybe && typeof (maybe as any).then === 'function'
            ? await maybe
            : maybe;
      } else {
        resolvedRegion = regionConfig as string;
      }

      const regionPart = resolvedRegion || 'us-east-1';

      if (makePublic) {
        const publicUrl = `https://${this.bucket}.s3.${regionPart}.amazonaws.com/${encodeURIComponent(key)}`;
        return { key, url: publicUrl, public: true };
      }

      // Return a presigned GET URL valid for 1 hour by default
      const expires = Number(
        this.config.get<number>('S3_PRESIGNED_EXPIRES') || 3600,
      );
      const getCmd = new GetObjectCommand({ Bucket: this.bucket, Key: key });
      const signedUrl = await getSignedUrl(this.client, getCmd, {
        expiresIn: expires,
      });
      return { key, url: signedUrl, public: false, expiresIn: expires };
    } catch (err) {
      console.log(err);
      console.log(err.message);

      throw new InternalServerErrorException('Failed to upload to S3');
    }
  }
}
