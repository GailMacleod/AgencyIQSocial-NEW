/**
 * CRITICAL FIX: Session Invalidation Middleware - HIGH SEVERITY
 * 
 * Problem: Sessions persist post-cancel causing stale UI menu bugs
 * Solution: Comprehensive session invalidation with React Query cache clearing
 */

import { Request, Response, NextFunction } from 'express';
import { db } from '../db';
import { eq } from 'drizzle-orm';
import { users } from '../../shared/schema';

export class SessionInvalidationManager {
  private static instance: SessionInvalidationManager;

  public static getInstance(): SessionInvalidationManager {
    if (!SessionInvalidationManager.instance) {
      SessionInvalidationManager.instance = new SessionInvalidationManager();
    }
    return SessionInvalidationManager.instance;
  }

  /**
   * CRITICAL: Complete session invalidation on subscription cancel
   */
  public async invalidateUserSession(req: any, res: Response): Promise<void> {
    const userId = req.session?.userId;
    
    if (!userId) {
      console.warn('🚨 [SESSION_INVALIDATION] No user session to invalidate');
      return;
    }

    try {
      // 1. Destroy server-side session
      await new Promise<void>((resolve, reject) => {
        req.session.destroy((err: any) => {
          if (err) {
            console.error('🚨 [SESSION_DESTROY] Failed to destroy session:', err);
            reject(err);
          } else {
            console.log('✅ [SESSION_DESTROY] Server session destroyed for user:', userId);
            resolve();
          }
        });
      });

      // 2. Clear all authentication cookies with proper attributes
      const cookieOptions = {
        httpOnly: true,
        secure: process.env.NODE_ENV === 'production',
        sameSite: 'strict' as const,
        path: '/api',
        partitioned: true
      };

      res.clearCookie('theagencyiq.session', cookieOptions);
      res.clearCookie('aiq_backup_session', { ...cookieOptions, path: '/' });
      res.clearCookie('connect.sid', cookieOptions);
      
      // 3. Set session invalidation flag for frontend
      res.cookie('session-invalidated', '1', {
        maxAge: 10 * 1000, // 10 seconds
        httpOnly: false, // Needs to be accessible to frontend
        secure: process.env.NODE_ENV === 'production',
        sameSite: 'strict'
      });

      // 4. Reset user quota to prevent stale "0/0" displays
      await db.update(users)
        .set({
          remainingPosts: 0,
          totalPosts: 0,
          subscriptionActive: false,
          subscriptionPlan: 'cancelled'
        })
        .where(eq(users.id, userId));

      console.log('✅ [SESSION_INVALIDATION] Complete session invalidation completed for user:', userId);

    } catch (error: any) {
      console.error('🚨 [SESSION_INVALIDATION] Failed to invalidate session:', error);
      throw error;
    }
  }

  /**
   * Session regeneration middleware for login/OAuth callbacks
   */
  public regenerateSession(req: any, res: Response, next: NextFunction): void {
    if (req.session) {
      req.session.regenerate((err: any) => {
        if (err) {
          console.error('🚨 [SESSION_REGEN] Session regeneration failed:', err);
          return res.status(500).json({
            error: 'Session security error',
            code: 'SESSION_REGENERATION_FAILED'
          });
        }
        
        console.log('✅ [SESSION_REGEN] Session regenerated successfully');
        next();
      });
    } else {
      next();
    }
  }

  /**
   * Check for stale sessions and force re-authentication
   */
  public checkStaleSession(req: any, res: Response, next: NextFunction): void {
    const userId = req.session?.userId;
    
    if (userId && req.session.createdAt) {
      const sessionAge = Date.now() - req.session.createdAt;
      const maxAge = 24 * 60 * 60 * 1000; // 24 hours
      
      if (sessionAge > maxAge) {
        console.log('🔒 [STALE_SESSION] Session expired, forcing re-authentication:', {
          userId,
          sessionAge: Math.round(sessionAge / (1000 * 60 * 60)) + 'h'
        });
        
        req.session.destroy(() => {
          res.clearCookie('theagencyiq.session');
          res.status(401).json({
            error: 'Session expired',
            code: 'STALE_SESSION_DETECTED',
            redirectTo: '/api/login'
          });
        });
        return;
      }
    }
    
    next();
  }
}

/**
 * Middleware for OAuth token revocation on cancel
 */
export const revokeOAuthTokens = async (userId: number): Promise<void> => {
  try {
    // Import platform connections dynamically to avoid ES conflicts
    const { platformConnections } = await import('../../shared/schema');
    
    // Get all active OAuth connections
    const connections = await db.select()
      .from(platformConnections)
      .where(eq(platformConnections.userId, userId.toString()));

    // Revoke each platform token
    for (const connection of connections) {
      try {
        const platform = connection.platform;
        const token = connection.token;
        
        if (!token) continue;

        // Platform-specific revocation
        switch (platform) {
          case 'facebook':
            await fetch(`https://graph.facebook.com/me/permissions?access_token=${token}`, {
              method: 'DELETE'
            });
            break;
          case 'linkedin':
            await fetch(`https://api.linkedin.com/v2/accessToken/${token}`, {
              method: 'DELETE',
              headers: { 'Authorization': `Bearer ${token}` }
            });
            break;
          // Add other platforms as needed
        }

        // Deactivate in database
        await db.update(platformConnections)
          .set({ 
            isActive: false,
            token: null,
            refreshToken: null 
          })
          .where(eq(platformConnections.id, connection.id));

        console.log(`✅ [OAUTH_REVOKE] Revoked ${platform} token for user ${userId}`);
      } catch (error) {
        console.error(`🚨 [OAUTH_REVOKE] Failed to revoke ${connection.platform}:`, error);
      }
    }
  } catch (error) {
    console.error('🚨 [OAUTH_REVOKE] Failed to revoke OAuth tokens:', error);
  }
};