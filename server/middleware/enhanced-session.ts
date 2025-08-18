// Enhanced Session Management with PostgreSQL Persistence
// Comprehensive session handling, regeneration, and touch middleware

import session from 'express-session';
import connectPg from 'connect-pg-simple';
import { Request, Response, NextFunction } from 'express';

const PgSession = connectPg(session);

// Enhanced session configuration with PostgreSQL backing
export const createEnhancedSession = () => {
  const sessionStore = new PgSession({
    conString: process.env.DATABASE_URL,
    tableName: 'sessions',
    createTableIfMissing: false, // Table created in schema
    ttl: 7 * 24 * 60 * 60, // 7 days in seconds
    disableTouch: false, // Enable touch for active session extension
    touchInterval: 60 * 1000, // Touch every minute for active users
  });

  return session({
    store: sessionStore,
    secret: process.env.SESSION_SECRET || 'fallback-secret-change-in-production',
    name: 'theagencyiq.session',
    resave: false,
    saveUninitialized: false,
    rolling: true, // Reset expiry on activity
    cookie: {
      secure: process.env.NODE_ENV === 'production',
      httpOnly: true,
      maxAge: 7 * 24 * 60 * 60 * 1000, // 7 days
      sameSite: 'strict'
    },
    genid: () => {
      // Generate session IDs with consistent format
      const timestamp = Date.now().toString(36);
      const random = Math.random().toString(36).substring(2, 15);
      return `aiq_${timestamp}_${random}`;
    }
  });
};

// Session regeneration middleware for security
export const regenerateSession = (req: Request, res: Response, next: NextFunction) => {
  const session = (req as any).session;
  
  if (session && typeof session.regenerate === 'function') {
    session.regenerate((err: any) => {
      if (err) {
        console.error('Session regeneration failed:', err);
        // Continue anyway to avoid blocking user
      }
      next();
    });
  } else {
    next();
  }
};

// Session touch middleware for active users
export const touchSession = (req: Request, res: Response, next: NextFunction) => {
  const session = (req as any).session;
  
  if (session && typeof session.touch === 'function') {
    try {
      session.touch();
      session.lastActivity = new Date();
    } catch (error) {
      console.error('Session touch failed:', error);
      // Continue anyway
    }
  }
  
  next();
};

// Session validation middleware
export const validateSessionHealth = (req: Request, res: Response, next: NextFunction) => {
  const session = (req as any).session;
  
  if (!session) {
    return res.status(401).json({
      error: 'No session found',
      code: 'NO_SESSION'
    });
  }

  // Check session format
  if (!session.id || !session.id.startsWith('aiq_')) {
    return res.status(401).json({
      error: 'Invalid session format',
      code: 'INVALID_SESSION_FORMAT'
    });
  }

  // Check session age (optional)
  const maxAge = 7 * 24 * 60 * 60 * 1000; // 7 days
  const sessionAge = Date.now() - new Date(session.cookie.originalMaxAge || Date.now()).getTime();
  
  if (sessionAge > maxAge) {
    return res.status(401).json({
      error: 'Session expired',
      code: 'SESSION_EXPIRED'
    });
  }

  next();
};

// Session establishment helper
export const establishSession = async (req: Request, res: Response, userData: any) => {
  const session = (req as any).session;
  
  try {
    // Regenerate session for security
    await new Promise<void>((resolve, reject) => {
      session.regenerate((err: any) => {
        if (err) reject(err);
        else resolve();
      });
    });

    // Set user data in session
    session.userId = userData.id;
    session.email = userData.email;
    session.authenticated = true;
    session.loginTime = new Date();

    // Save session
    await new Promise<void>((resolve, reject) => {
      session.save((err: any) => {
        if (err) reject(err);
        else resolve();
      });
    });

    return {
      success: true,
      sessionId: session.id,
      message: 'Session established successfully'
    };
  } catch (error) {
    console.error('Session establishment failed:', error);
    return {
      success: false,
      error: 'Failed to establish session'
    };
  }
};

// Session cleanup helper
export const cleanupSession = (req: Request, res: Response) => {
  const session = (req as any).session;
  
  if (session) {
    return new Promise<void>((resolve) => {
      session.destroy((err: any) => {
        if (err) {
          console.error('Session destruction failed:', err);
        }
        
        // Clear cookies
        res.clearCookie('theagencyiq.session');
        res.clearCookie('connect.sid');
        res.clearCookie('aiq_backup_session');
        
        resolve();
      });
    });
  }
  
  return Promise.resolve();
};

// Session debugging middleware (development only)
export const debugSession = (req: Request, res: Response, next: NextFunction) => {
  if (process.env.NODE_ENV === 'development') {
    const session = (req as any).session;
    console.log('🔍 Session Debug', {
      path: req.path,
      sessionId: session?.id,
      userId: session?.userId,
      authenticated: session?.authenticated,
      lastActivity: session?.lastActivity
    });
  }
  next();
};

// Session metrics collection
export const collectSessionMetrics = (req: Request, res: Response, next: NextFunction) => {
  const session = (req as any).session;
  
  if (session) {
    // Track session activity
    if (!session.metrics) {
      session.metrics = {
        requestCount: 0,
        firstRequest: new Date(),
        lastRequest: new Date()
      };
    }
    
    session.metrics.requestCount++;
    session.metrics.lastRequest = new Date();
  }
  
  next();
};