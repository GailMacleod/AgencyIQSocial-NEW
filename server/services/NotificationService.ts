// Comprehensive Notification Service with SendGrid and Twilio Integration
// Handles email, SMS, and notification tracking with proper logging

import sgMail from '@sendgrid/mail';
import twilio from 'twilio';
import { db } from '../db';
import { notificationLogs, users } from '../../shared/schema';
import { eq } from 'drizzle-orm';
import { logger } from '../utils/logger.js';

export interface NotificationConfig {
  sendgridApiKey?: string;
  twilioAccountSid?: string;
  twilioAuthToken?: string;
  twilioPhoneNumber?: string;
  fromEmail?: string;
}

export interface EmailNotification {
  to: string;
  subject: string;
  content: string;
  html?: string;
  templateId?: string;
  dynamicTemplateData?: any;
}

export interface SMSNotification {
  to: string;
  content: string;
}

export class NotificationService {
  private twilioClient: any;
  private isConfigured: {
    sendgrid: boolean;
    twilio: boolean;
  };

  constructor(config?: NotificationConfig) {
    this.isConfigured = {
      sendgrid: false,
      twilio: false
    };

    this.initialize(config);
  }

  private initialize(config?: NotificationConfig) {
    // Initialize SendGrid
    const sendgridKey = config?.sendgridApiKey || process.env.SENDGRID_API_KEY;
    if (sendgridKey) {
      sgMail.setApiKey(sendgridKey);
      this.isConfigured.sendgrid = true;
      logger.info('SendGrid initialized successfully');
    } else {
      logger.warn('SendGrid not configured - email notifications disabled');
    }

    // Initialize Twilio
    const twilioSid = config?.twilioAccountSid || process.env.TWILIO_ACCOUNT_SID;
    const twilioToken = config?.twilioAuthToken || process.env.TWILIO_AUTH_TOKEN;
    
    if (twilioSid && twilioToken) {
      this.twilioClient = twilio(twilioSid, twilioToken);
      this.isConfigured.twilio = true;
      logger.info('Twilio initialized successfully');
    } else {
      logger.warn('Twilio not configured - SMS notifications disabled');
    }
  }

  async sendEmail(userId: number, notification: EmailNotification): Promise<boolean> {
    if (!this.isConfigured.sendgrid) {
      logger.warn('Attempted to send email but SendGrid not configured', { userId });
      return false;
    }

    try {
      const emailData: any = {
        to: notification.to,
        from: process.env.FROM_EMAIL || 'noreply@theagencyiq.ai',
        subject: notification.subject,
      };

      // Use template or plain content
      if (notification.templateId) {
        emailData.templateId = notification.templateId;
        emailData.dynamicTemplateData = notification.dynamicTemplateData || {};
      } else {
        emailData.text = notification.content;
        if (notification.html) {
          emailData.html = notification.html;
        }
      }

      const response = await sgMail.send(emailData);
      const messageId = response[0]?.headers?.['x-message-id'];

      // Log successful notification
      await this.logNotification(userId, {
        type: 'email',
        provider: 'sendgrid',
        recipient: notification.to,
        subject: notification.subject,
        content: notification.content,
        status: 'sent',
        externalId: messageId
      });

      logger.info('Email sent successfully', {
        userId,
        recipient: notification.to,
        messageId
      });

      return true;
    } catch (error) {
      await this.logNotification(userId, {
        type: 'email',
        provider: 'sendgrid',
        recipient: notification.to,
        subject: notification.subject,
        content: notification.content,
        status: 'failed',
        errorMessage: error.message
      });

      logger.error('Email sending failed', {
        userId,
        recipient: notification.to,
        error: error.message
      });

      return false;
    }
  }

  async sendSMS(userId: number, notification: SMSNotification): Promise<boolean> {
    if (!this.isConfigured.twilio) {
      logger.warn('Attempted to send SMS but Twilio not configured', { userId });
      return false;
    }

    try {
      const message = await this.twilioClient.messages.create({
        body: notification.content,
        from: process.env.TWILIO_PHONE_NUMBER,
        to: notification.to
      });

      // Log successful notification
      await this.logNotification(userId, {
        type: 'sms',
        provider: 'twilio',
        recipient: notification.to,
        subject: null,
        content: notification.content,
        status: 'sent',
        externalId: message.sid
      });

      logger.info('SMS sent successfully', {
        userId,
        recipient: notification.to,
        messageSid: message.sid
      });

      return true;
    } catch (error) {
      await this.logNotification(userId, {
        type: 'sms',
        provider: 'twilio',
        recipient: notification.to,
        subject: null,
        content: notification.content,
        status: 'failed',
        errorMessage: error.message
      });

      logger.error('SMS sending failed', {
        userId,
        recipient: notification.to,
        error: error.message
      });

      return false;
    }
  }

  async sendPostConfirmation(userId: number, postData: {
    platform: string;
    content: string;
    postId: string;
  }): Promise<void> {
    try {
      const [user] = await db.select().from(users).where(eq(users.id, userId));
      if (!user) {
        logger.warn('User not found for post confirmation', { userId });
        return;
      }

      // Send email confirmation
      if (user.email && this.isConfigured.sendgrid) {
        await this.sendEmail(userId, {
          to: user.email,
          subject: `Post Published Successfully on ${postData.platform}`,
          content: `Your post has been successfully published on ${postData.platform}.\n\nContent: ${postData.content.substring(0, 100)}...\n\nPost ID: ${postData.postId}`,
          html: `
            <h2>Post Published Successfully</h2>
            <p>Your post has been successfully published on <strong>${postData.platform}</strong>.</p>
            <div style="background: #f5f5f5; padding: 15px; margin: 10px 0; border-left: 4px solid #007bff;">
              <p><strong>Content:</strong> ${postData.content.substring(0, 200)}...</p>
            </div>
            <p><strong>Post ID:</strong> ${postData.postId}</p>
            <p>Thank you for using TheAgencyIQ!</p>
          `
        });
      }

      // Send SMS confirmation if phone available
      if (user.phone && this.isConfigured.twilio) {
        await this.sendSMS(userId, {
          to: user.phone,
          content: `✅ Your post was published successfully on ${postData.platform}. Post ID: ${postData.postId}`
        });
      }
    } catch (error) {
      logger.error('Post confirmation notification failed', {
        userId,
        postId: postData.postId,
        error: error.message
      });
    }
  }

  async sendErrorNotification(userId: number, errorData: {
    platform: string;
    errorMessage: string;
    postId: string;
    attemptNumber: number;
  }): Promise<void> {
    try {
      const [user] = await db.select().from(users).where(eq(users.id, userId));
      if (!user) {
        logger.warn('User not found for error notification', { userId });
        return;
      }

      // Send email notification for posting errors
      if (user.email && this.isConfigured.sendgrid) {
        await this.sendEmail(userId, {
          to: user.email,
          subject: `Posting Issue on ${errorData.platform} - Attempt ${errorData.attemptNumber}`,
          content: `There was an issue posting to ${errorData.platform}.\n\nError: ${errorData.errorMessage}\n\nPost ID: ${errorData.postId}\n\nWe're automatically retrying the post.`,
          html: `
            <h2>Posting Issue Detected</h2>
            <p>There was an issue posting to <strong>${errorData.platform}</strong>.</p>
            <div style="background: #fff3cd; padding: 15px; margin: 10px 0; border-left: 4px solid #ffc107;">
              <p><strong>Error:</strong> ${errorData.errorMessage}</p>
              <p><strong>Post ID:</strong> ${errorData.postId}</p>
              <p><strong>Attempt:</strong> ${errorData.attemptNumber}</p>
            </div>
            <p>We're automatically retrying the post. You'll receive a confirmation when it succeeds.</p>
          `
        });
      }
    } catch (error) {
      logger.error('Error notification sending failed', {
        userId,
        postId: errorData.postId,
        error: error.message
      });
    }
  }

  async sendOTPVerification(phone: string, otp: string): Promise<boolean> {
    if (!this.isConfigured.twilio) {
      logger.warn('Attempted to send OTP but Twilio not configured');
      return false;
    }

    try {
      const message = await this.twilioClient.messages.create({
        body: `Your TheAgencyIQ verification code is: ${otp}. This code expires in 10 minutes.`,
        from: process.env.TWILIO_PHONE_NUMBER,
        to: phone
      });

      logger.info('OTP sent successfully', {
        phone: phone.substring(0, 6) + '***',
        messageSid: message.sid
      });

      return true;
    } catch (error) {
      logger.error('OTP sending failed', {
        phone: phone.substring(0, 6) + '***',
        error: error.message
      });
      return false;
    }
  }

  async sendEmailVerification(email: string, verificationCode: string, verificationUrl: string): Promise<boolean> {
    if (!this.isConfigured.sendgrid) {
      logger.warn('Attempted to send email verification but SendGrid not configured');
      return false;
    }

    try {
      await sgMail.send({
        to: email,
        from: process.env.FROM_EMAIL || 'noreply@theagencyiq.ai',
        subject: 'Verify Your TheAgencyIQ Account',
        html: `
          <h2>Welcome to TheAgencyIQ!</h2>
          <p>Please verify your email address to complete your account setup.</p>
          <div style="background: #f8f9fa; padding: 20px; margin: 20px 0; text-align: center;">
            <h3>Verification Code: ${verificationCode}</h3>
            <p>Or click the link below:</p>
            <a href="${verificationUrl}" style="background: #007bff; color: white; padding: 12px 24px; text-decoration: none; border-radius: 4px;">Verify Email</a>
          </div>
          <p>This verification code expires in 24 hours.</p>
          <p>If you didn't create an account with TheAgencyIQ, please ignore this email.</p>
        `
      });

      logger.info('Email verification sent successfully', {
        email: email.substring(0, 3) + '***@' + email.split('@')[1]
      });

      return true;
    } catch (error) {
      logger.error('Email verification sending failed', {
        email: email.substring(0, 3) + '***@' + email.split('@')[1],
        error: error.message
      });
      return false;
    }
  }

  private async logNotification(userId: number, data: {
    type: string;
    provider: string;
    recipient: string;
    subject: string | null;
    content: string;
    status: string;
    externalId?: string;
    errorMessage?: string;
  }) {
    try {
      await db.insert(notificationLogs).values({
        userId,
        type: data.type,
        provider: data.provider,
        recipient: data.recipient,
        subject: data.subject,
        content: data.content,
        status: data.status,
        externalId: data.externalId,
        errorMessage: data.errorMessage,
        sentAt: data.status === 'sent' ? new Date() : null
      });
    } catch (error) {
      logger.error('Failed to log notification', {
        error: error.message,
        userId,
        type: data.type
      });
    }
  }

  // Get notification status and logs for a user
  async getNotificationHistory(userId: number, limit: number = 50) {
    try {
      const logs = await db.select()
        .from(notificationLogs)
        .where(eq(notificationLogs.userId, userId))
        .orderBy(notificationLogs.createdAt)
        .limit(limit);

      return logs;
    } catch (error) {
      logger.error('Failed to get notification history', {
        error: error.message,
        userId
      });
      return [];
    }
  }

  // Check service status
  getServiceStatus() {
    return {
      sendgrid: {
        configured: this.isConfigured.sendgrid,
        service: 'Email notifications'
      },
      twilio: {
        configured: this.isConfigured.twilio,
        service: 'SMS notifications'
      }
    };
  }
}

// Export singleton instance
export const notificationService = new NotificationService();