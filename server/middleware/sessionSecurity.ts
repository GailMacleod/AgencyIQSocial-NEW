import { Request, Response, NextFunction } from 'express';

interface SecureRequest extends Request {
  session: any;
}

// Session security middleware for enhanced protection
export function sessionSecurityMiddleware(req: SecureRequest, res: Response, next: NextFunction) {
  // Regenerate session ID on login to prevent fixation attacks
  if (req.path === '/api/login' && req.method === 'POST' && req.session?.userId) {
    req.session.regenerate((err: any) => {
      if (err) {
        console.error('Session regeneration failed:', err);
      } else {
        console.log('🔐 Session ID regenerated for security');
      }
      next();
    });
    return;
  }

  // Monitor for suspicious activity (IP/User-Agent changes)
  if (req.session?.userId) {
    const currentIP = req.ip || req.connection.remoteAddress;
    const currentUA = req.headers['user-agent'];
    
    if (req.session.lastIP && req.session.lastIP !== currentIP) {
      console.log('⚠️ IP change detected - potential session hijacking:', {
        userId: req.session.userId,
        oldIP: req.session.lastIP,
        newIP: currentIP
      });
      
      // In production, you might want to invalidate the session
      // req.session.destroy();
      // return res.status(401).json({ error: 'Session invalidated due to suspicious activity' });
    }
    
    if (req.session.lastUA && req.session.lastUA !== currentUA) {
      console.log('⚠️ User-Agent change detected:', {
        userId: req.session.userId,
        change: 'User-Agent mismatch'
      });
    }
    
    // Update session tracking
    req.session.lastIP = currentIP;
    req.session.lastUA = currentUA;
    req.session.lastActivity = new Date().toISOString();
  }

  next();
}

// Auto-logout on inactivity middleware
export function inactivityTimeoutMiddleware(req: SecureRequest, res: Response, next: NextFunction) {
  if (req.session?.userId && req.session.lastActivity) {
    const lastActivity = new Date(req.session.lastActivity);
    const now = new Date();
    const inactiveMinutes = (now.getTime() - lastActivity.getTime()) / (1000 * 60);
    
    // 30 minutes inactivity timeout
    if (inactiveMinutes > 30) {
      console.log('⏰ Session expired due to inactivity:', {
        userId: req.session.userId,
        inactiveMinutes: Math.round(inactiveMinutes)
      });
      
      req.session.destroy((err: any) => {
        if (err) {
          console.error('Session destruction failed:', err);
        }
        res.clearCookie('theagencyiq.session');
        res.clearCookie('aiq_backup_session');
        return res.status(401).json({ error: 'Session expired due to inactivity' });
      });
      return;
    }
  }

  next();
}

// Secure logout with comprehensive cleanup
export function secureLogoutHandler(req: SecureRequest, res: Response) {
  if (req.session) {
    req.session.destroy((err: any) => {
      if (err) {
        console.error('Logout session destruction failed:', err);
        return res.status(500).json({ error: 'Logout failed' });
      }
      
      // Clear all session cookies
      res.clearCookie('theagencyiq.session', {
        path: '/',
        httpOnly: true,
        secure: process.env.NODE_ENV === 'production',
        sameSite: 'strict'
      });
      
      res.clearCookie('aiq_backup_session', {
        path: '/',
        httpOnly: true,
        secure: process.env.NODE_ENV === 'production',
        sameSite: 'strict'
      });
      
      console.log('🔐 Secure logout completed - all cookies cleared');
      res.json({ success: true, message: 'Logged out successfully' });
    });
  } else {
    res.json({ success: true, message: 'No active session' });
  }
}