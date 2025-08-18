// Phone/Password Authentication Routes
// Handles login, password reset, and user verification

import { Router } from 'express';
import bcrypt from 'bcrypt';
import { db } from '../db';
import { users } from '../../shared/schema';
import { eq } from 'drizzle-orm';
import { authRateLimit, logSecurityEvent } from '../middleware/enhanced-security';
import { establishSession } from '../middleware/enhanced-session';
import { notificationService } from '../services/NotificationService';

const router = Router();

// Phone/Password Login endpoint
router.post('/api/auth/login',
  authRateLimit,
  logSecurityEvent('LOGIN_ATTEMPT'),
  async (req, res) => {
    try {
      const { phone, password } = req.body;

      if (!phone || !password) {
        return res.status(400).json({
          error: 'Phone number and password required',
          code: 'MISSING_CREDENTIALS'
        });
      }

      // Find user by phone number
      const [user] = await db.select()
        .from(users)
        .where(eq(users.phone, phone));

      if (!user) {
        return res.status(401).json({
          error: 'Invalid phone number or password',
          code: 'INVALID_CREDENTIALS'
        });
      }

      // Verify password
      const passwordValid = await bcrypt.compare(password, user.password);
      
      if (!passwordValid) {
        console.log('[SECURITY] Failed login attempt', {
          phone,
          ip: req.ip,
          userAgent: req.headers['user-agent']
        });
        
        return res.status(401).json({
          error: 'Invalid phone number or password',
          code: 'INVALID_CREDENTIALS'
        });
      }

      // Establish session
      const sessionResult = await establishSession(req, res, {
        id: user.id,
        email: user.email,
        phone: user.phone,
        subscriptionPlan: user.subscriptionPlan,
        subscriptionActive: user.subscriptionActive
      });

      if (sessionResult.success) {
        console.log('[AUTH] Successful login', {
          userId: user.id,
          email: user.email,
          phone: user.phone,
          sessionId: sessionResult.sessionId
        });

        res.json({
          success: true,
          message: 'Login successful',
          user: {
            id: user.id,
            email: user.email,
            phone: user.phone,
            subscriptionPlan: user.subscriptionPlan,
            subscriptionActive: user.subscriptionActive
          },
          sessionId: sessionResult.sessionId
        });
      } else {
        res.status(500).json({
          error: 'Failed to establish session',
          code: 'SESSION_ERROR'
        });
      }
    } catch (error) {
      console.error('Login error:', error);
      res.status(500).json({
        error: 'Login failed',
        code: 'LOGIN_ERROR'
      });
    }
  }
);

// Password reset request
router.post('/api/auth/forgot-password',
  authRateLimit,
  async (req, res) => {
    try {
      const { phone } = req.body;

      if (!phone) {
        return res.status(400).json({
          error: 'Phone number required',
          code: 'MISSING_PHONE'
        });
      }

      // Find user by phone
      const [user] = await db.select()
        .from(users)
        .where(eq(users.phone, phone));

      if (!user) {
        // Don't reveal if user exists or not
        return res.json({
          success: true,
          message: 'If this phone number exists, a reset code will be sent'
        });
      }

      // Generate 6-digit reset code
      const resetCode = Math.floor(100000 + Math.random() * 900000).toString();
      
      // Store reset code in session for verification
      (req as any).session.passwordResetCode = resetCode;
      (req as any).session.passwordResetPhone = phone;
      (req as any).session.passwordResetExpiry = Date.now() + 10 * 60 * 1000; // 10 minutes

      // Send SMS with reset code
      const smsSent = await notificationService.sendSMS(user.id.toString(), {
        to: phone,
        content: `Your TheAgencyIQ password reset code is: ${resetCode}. This code expires in 10 minutes.`
      });

      if (smsSent) {
        res.json({
          success: true,
          message: 'Reset code sent to your phone'
        });
      } else {
        res.status(500).json({
          error: 'Failed to send reset code',
          code: 'SMS_SEND_FAILED'
        });
      }
    } catch (error) {
      console.error('Password reset request failed:', error);
      res.status(500).json({
        error: 'Password reset request failed',
        code: 'RESET_REQUEST_ERROR'
      });
    }
  }
);

// Verify reset code and update password
router.post('/api/auth/reset-password',
  authRateLimit,
  async (req, res) => {
    try {
      const { phone, resetCode, newPassword } = req.body;
      const session = (req as any).session;

      if (!phone || !resetCode || !newPassword) {
        return res.status(400).json({
          error: 'Phone, reset code, and new password required',
          code: 'MISSING_FIELDS'
        });
      }

      // Verify reset code from session
      if (!session.passwordResetCode || 
          !session.passwordResetPhone || 
          !session.passwordResetExpiry) {
        return res.status(400).json({
          error: 'No active password reset request',
          code: 'NO_RESET_REQUEST'
        });
      }

      if (Date.now() > session.passwordResetExpiry) {
        return res.status(400).json({
          error: 'Reset code expired',
          code: 'CODE_EXPIRED'
        });
      }

      if (session.passwordResetCode !== resetCode || 
          session.passwordResetPhone !== phone) {
        return res.status(400).json({
          error: 'Invalid reset code or phone number',
          code: 'INVALID_CODE'
        });
      }

      // Hash new password
      const hashedPassword = await bcrypt.hash(newPassword, 10);

      // Update password in database
      await db.update(users)
        .set({ 
          password: hashedPassword,
          updatedAt: new Date()
        })
        .where(eq(users.phone, phone));

      // Clear reset session data
      delete session.passwordResetCode;
      delete session.passwordResetPhone;
      delete session.passwordResetExpiry;

      console.log('[AUTH] Password reset successful', {
        phone,
        ip: req.ip
      });

      res.json({
        success: true,
        message: 'Password updated successfully'
      });
    } catch (error) {
      console.error('Password reset failed:', error);
      res.status(500).json({
        error: 'Password reset failed',
        code: 'RESET_ERROR'
      });
    }
  }
);

// Check if user exists by phone
router.post('/api/auth/check-user',
  async (req, res) => {
    try {
      const { phone } = req.body;

      if (!phone) {
        return res.status(400).json({
          error: 'Phone number required',
          code: 'MISSING_PHONE'
        });
      }

      const [user] = await db.select({ id: users.id, email: users.email })
        .from(users)
        .where(eq(users.phone, phone));

      res.json({
        exists: !!user,
        email: user?.email || null
      });
    } catch (error) {
      console.error('User check failed:', error);
      res.status(500).json({
        error: 'User check failed',
        code: 'CHECK_ERROR'
      });
    }
  }
);

// Get current user from session
router.get('/api/auth/user',
  async (req, res) => {
    try {
      const session = (req as any).session;
      
      if (!session || !session.userId) {
        return res.status(401).json({
          error: 'Not authenticated',
          code: 'NOT_AUTHENTICATED'
        });
      }

      const [user] = await db.select()
        .from(users)
        .where(eq(users.id, session.userId));

      if (!user) {
        return res.status(404).json({
          error: 'User not found',
          code: 'USER_NOT_FOUND'
        });
      }

      res.json({
        id: user.id,
        email: user.email,
        phone: user.phone,
        subscriptionPlan: user.subscriptionPlan,
        subscriptionActive: user.subscriptionActive,
        userId: user.userId
      });
    } catch (error) {
      console.error('Get user failed:', error);
      res.status(500).json({
        error: 'Failed to get user',
        code: 'GET_USER_ERROR'
      });
    }
  }
);

// Logout endpoint
router.post('/api/auth/logout',
  logSecurityEvent('LOGOUT'),
  async (req, res) => {
    try {
      const session = (req as any).session;
      
      if (session) {
        await new Promise<void>((resolve) => {
          session.destroy((err: any) => {
            if (err) {
              console.error('Session destruction failed:', err);
            }
            resolve();
          });
        });
      }

      // Clear all cookies
      res.clearCookie('theagencyiq.session');
      res.clearCookie('connect.sid');
      res.clearCookie('aiq_backup_session');

      res.json({
        success: true,
        message: 'Logged out successfully'
      });
    } catch (error) {
      console.error('Logout failed:', error);
      res.status(500).json({
        error: 'Logout failed',
        code: 'LOGOUT_ERROR'
      });
    }
  }
);

export default router;