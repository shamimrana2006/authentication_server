import { Injectable } from '@nestjs/common';
import { MailerService } from '@nestjs-modules/mailer';

@Injectable()
export class EmailService {
  constructor(private mailerService: MailerService) {}

  async sendVerificationOtp(email: string, otp: string, name: string) {
    await this.mailerService.sendMail({
      to: email,
      subject: 'Email Verification OTP',
      html: `
        <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;">
          <h2>Email Verification</h2>
          <p>Hi ${name},</p>
          <p>Your verification code is:</p>
          <h1 style="color: #4CAF50; font-size: 32px; letter-spacing: 5px;">${otp}</h1>
          <p>This code will expire in 10 minutes.</p>
          <p>If you didn't request this, please ignore this email.</p>
        </div>
      `,
    });
  }

  async sendPasswordResetOtp(email: string, otp: string, name: string) {
    await this.mailerService.sendMail({
      to: email,
      subject: 'Password Reset OTP',
      html: `
        <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;">
          <h2>Password Reset Request</h2>
          <p>Hi ${name},</p>
          <p>Your password reset code is:</p>
          <h1 style="color: #FF5722; font-size: 32px; letter-spacing: 5px;">${otp}</h1>
          <p>This code will expire in 10 minutes.</p>
          <p>If you didn't request this, please ignore this email and your password will remain unchanged.</p>
        </div>
      `,
    });
  }

  async sendUsernameReminder(email: string, username: string, name: string) {
    await this.mailerService.sendMail({
      to: email,
      subject: 'Your Username',
      html: `
        <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;">
          <h2>Username Reminder</h2>
          <p>Hi ${name},</p>
          <p>Your username is: <strong>${username}</strong></p>
          <p>If you didn't request this, please contact support.</p>
        </div>
      `,
    });
  }

  async sendPasswordChangedNotification(email: string, name: string) {
    await this.mailerService.sendMail({
      to: email,
      subject: 'Password Changed Successfully',
      html: `
        <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;">
          <h2>Password Changed</h2>
          <p>Hi ${name},</p>
          <p>Your password has been successfully changed.</p>
          <p>If you didn't make this change, please contact support immediately.</p>
        </div>
      `,
    });
  }

  async sendGoogleAuthPassword(
    email: string,
    password: string,
    username: string,
    name: string,
  ) {
    await this.mailerService.sendMail({
      to: email,
      subject: 'Welcome! Your Account Password',
      html: `
        <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;">
          <h2 style="color: #4CAF50;">Welcome to Our Platform!</h2>
          <p>Hi ${name},</p>
          
          <p>Your account has been created successfully via Google Sign-In.</p>
          
          <p>Here are your login credentials for future reference:</p>
          
          <div style="background-color: #f5f5f5; padding: 20px; border-radius: 8px; margin: 20px 0;">
            <p style="margin: 10px 0;"><strong>Username:</strong> ${username}</p>
            <p style="margin: 10px 0;"><strong>Email:</strong> ${email}</p>
            <p style="margin: 10px 0;"><strong>Password:</strong> <code style="background-color: #e0e0e0; padding: 5px 10px; border-radius: 4px;">${password}</code></p>
          </div>
          
          <div style="background-color: #fff3cd; padding: 15px; border-radius: 8px; border-left: 4px solid #ffc107; margin: 20px 0;">
            <p style="margin: 0; color: #856404;"><strong>⚠️ Security Notice:</strong></p>
            <p style="margin: 10px 0; color: #856404;">Please keep this password secure. We recommend changing it on your first login.</p>
            <p style="margin: 0; color: #856404;">You can also continue using Google Sign-In for future logins.</p>
          </div>
          
          <p style="margin-top: 20px;">If you have any questions or didn't create this account, please contact us immediately.</p>
          
          <p style="color: #666; font-size: 12px; margin-top: 30px;">
            This is an automated message. Please do not reply to this email.
          </p>
        </div>
      `,
    });
  }
}
