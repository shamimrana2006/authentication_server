import { Injectable, OnModuleDestroy, OnModuleInit } from '@nestjs/common';
import { CreatePrismaDto } from './dto/create-prisma.dto';
import { UpdatePrismaDto } from './dto/update-prisma.dto';
// import 'dotenv/config';

import { PrismaPg } from '@prisma/adapter-pg';
import { PrismaClient } from 'generated/client';
import { ConfigService } from '@nestjs/config';

@Injectable()
export class PrismaService implements OnModuleInit, OnModuleDestroy {
  private prisma: PrismaClient;
  constructor(private readonly env: ConfigService) {
    const adapter = new PrismaPg({
      connectionString: this.env.get<string>('DATABASE_URL') || '',
    });

    console.log(this.env.get<string>('DATABASE_URL'));

    this.prisma = new PrismaClient({
      adapter,
      log: [{ emit: 'event', level: 'error' }],
    });
  }
  async onModuleInit() {
    await this.prisma.$connect();
    console.log('data base connected');
  }

  async onModuleDestroy() {
    await this.prisma.$disconnect();
  }

  get client() {
    return this.prisma;
  }
}
