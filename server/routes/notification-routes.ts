// Notification Management Routes
// SendGrid email and Twilio SMS integration with comprehensive logging

import { Router } from 'express';
import { requireAuth, requireActiveSubscription } from '../middleware/auth-validation';
import { notificationService } from '../services/NotificationService';
import { authRateLimit } from '../middleware/enhanced-security';

const router = Router();

// Send verification email
router.post('/api/notifications/verify-email',
  authRateLimit,
  async (req, res) => {
    try {
      const { email, verificationCode, verificationUrl } = req.body;

      if (!email || !verificationCode || !verificationUrl) {
        return res.status(400).json({
          error: 'Email, verification code, and URL required',
          code: 'MISSING_REQUIRED_FIELDS'
        });
      }

      const sent = await notificationService.sendEmailVerification(
        email,
        verificationCode,
        verificationUrl
      );

      if (sent) {
        res.json({
          success: true,
          message: 'Verification email sent successfully'
        });
      } else {
        res.status(500).json({
          error: 'Failed to send verification email',
          code: 'EMAIL_SEND_FAILED'
        });
      }
    } catch (error) {
      console.error('Email verification failed:', error);
      res.status(500).json({
        error: 'Email verification failed',
        code: 'EMAIL_VERIFICATION_ERROR'
      });
    }
  }
);

// Send SMS OTP
router.post('/api/notifications/send-otp',
  authRateLimit,
  async (req, res) => {
    try {
      const { phone, otp } = req.body;

      if (!phone || !otp) {
        return res.status(400).json({
          error: 'Phone number and OTP required',
          code: 'MISSING_REQUIRED_FIELDS'
        });
      }

      const sent = await notificationService.sendOTPVerification(phone, otp);

      if (sent) {
        res.json({
          success: true,
          message: 'OTP sent successfully'
        });
      } else {
        res.status(500).json({
          error: 'Failed to send OTP',
          code: 'SMS_SEND_FAILED'
        });
      }
    } catch (error) {
      console.error('OTP sending failed:', error);
      res.status(500).json({
        error: 'OTP sending failed',
        code: 'OTP_SEND_ERROR'
      });
    }
  }
);

// Send custom email notification
router.post('/api/notifications/email',
  requireAuth,
  async (req, res) => {
    try {
      const { to, subject, content, html, templateId, dynamicTemplateData } = req.body;
      const userId = req.user!.id;

      if (!to || !subject || !content) {
        return res.status(400).json({
          error: 'To, subject, and content required',
          code: 'MISSING_REQUIRED_FIELDS'
        });
      }

      const sent = await notificationService.sendEmail(userId, {
        to,
        subject,
        content,
        html,
        templateId,
        dynamicTemplateData
      });

      if (sent) {
        res.json({
          success: true,
          message: 'Email sent successfully'
        });
      } else {
        res.status(500).json({
          error: 'Failed to send email',
          code: 'EMAIL_SEND_FAILED'
        });
      }
    } catch (error) {
      console.error('Email sending failed:', error);
      res.status(500).json({
        error: 'Email sending failed',
        code: 'EMAIL_SEND_ERROR'
      });
    }
  }
);

// Send SMS notification
router.post('/api/notifications/sms',
  requireAuth,
  async (req, res) => {
    try {
      const { to, content } = req.body;
      const userId = req.user!.id;

      if (!to || !content) {
        return res.status(400).json({
          error: 'To and content required',
          code: 'MISSING_REQUIRED_FIELDS'
        });
      }

      const sent = await notificationService.sendSMS(userId, {
        to,
        content
      });

      if (sent) {
        res.json({
          success: true,
          message: 'SMS sent successfully'
        });
      } else {
        res.status(500).json({
          error: 'Failed to send SMS',
          code: 'SMS_SEND_FAILED'
        });
      }
    } catch (error) {
      console.error('SMS sending failed:', error);
      res.status(500).json({
        error: 'SMS sending failed',
        code: 'SMS_SEND_ERROR'
      });
    }
  }
);

// Get notification history
router.get('/api/notifications/history',
  requireAuth,
  async (req, res) => {
    try {
      const userId = req.user!.id;
      const limit = parseInt(req.query.limit as string) || 50;

      const history = await notificationService.getNotificationHistory(userId, limit);

      res.json({
        success: true,
        notifications: history,
        count: history.length
      });
    } catch (error) {
      console.error('Failed to get notification history:', error);
      res.status(500).json({
        error: 'Failed to get notification history',
        code: 'HISTORY_ERROR'
      });
    }
  }
);

// Get notification service status
router.get('/api/notifications/status',
  requireAuth,
  async (req, res) => {
    try {
      const status = notificationService.getServiceStatus();

      res.json({
        success: true,
        services: status
      });
    } catch (error) {
      console.error('Failed to get notification status:', error);
      res.status(500).json({
        error: 'Failed to get notification status',
        code: 'STATUS_ERROR'
      });
    }
  }
);

export default router;