import {
  Injectable,
  ConflictException,
  NotFoundException,
} from '@nestjs/common';
import { CreateUserDto } from './dto/create-user.dto';
import { UpdateUserDto } from './dto/update-user.dto';
import { PrismaService } from '../lib/prisma/prisma.service';
import * as bcrypt from 'bcryptjs';
import { hashText } from '@/common/hashText';

@Injectable()
export class UserService {
  constructor(private prisma: PrismaService) {}

  async create(createUserDto: CreateUserDto) {
    try {
      // Check if user already exists
      const existingUser = await this.prisma.client.user.findFirst({
        where: {
          OR: [
            { email: createUserDto.email },
            { username: createUserDto.username },
          ],
        },
      });

      if (existingUser) {
        return new ConflictException(
          `Email${createUserDto.username ? '/Username' : ''} already in use in another account`,
        );
      }

      // Hash password if provided
      let hashedPassword: string | undefined;
      if (createUserDto.password) {
        hashedPassword = await hashText(createUserDto.password);
      }

      // Create user
      const user = await this.prisma.client.user.create({
        data: {
          email: createUserDto.email,
          username: createUserDto.username,
          password: hashedPassword,
          name: createUserDto.name,
          avatar: createUserDto.avatar,
          emailVerified: createUserDto.emailVerified || false,
        },
        select: {
          id: true,
          email: true,
          username: true,
          name: true,
          avatar: true,
          emailVerified: true,
          role: true,
          isActive: true,
          createdAt: true,
          updatedAt: true,
        },
      });
      return user;
    } catch (error) {
      console.log('this is error mssage:', error.message);
      throw error;
    }
  }

  async findAll() {
    return await this.prisma.client.user.findMany({
      select: {
        id: true,
        email: true,
        username: true,
        name: true,
        avatar: true,
        emailVerified: true,
        role: true,
        isActive: true,
        createdAt: true,
        updatedAt: true,
      },
      orderBy: {
        createdAt: 'desc',
      },
    });
  }

  async findOne(id: string) {
    const user = await this.prisma.client.user.findUnique({
      where: { id },
      select: {
        id: true,
        email: true,
        username: true,
        name: true,
        avatar: true,
        emailVerified: true,
        role: true,
        isActive: true,
        createdAt: true,
        updatedAt: true,
      },
    });

    if (!user) {
      throw new NotFoundException(`User with ID ${id} not found`);
    }

    return user;
  }

  update(id: number, updateUserDto: UpdateUserDto) {
    return `This action updates a #${id} user`;
  }

  remove(id: number) {
    return `This action removes a #${id} user`;
  }
}
