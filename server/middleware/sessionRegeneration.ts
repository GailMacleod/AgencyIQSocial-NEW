import { Request, Response, NextFunction } from 'express';

interface AuthRequest extends Request {
  session: any;
}

// Session regeneration middleware for login security
export function sessionRegenerationMiddleware(req: AuthRequest, res: Response, next: NextFunction) {
  // Only regenerate for login endpoints
  if (req.path === '/api/auth/login' && req.method === 'POST') {
    const originalSessionData = { ...req.session };
    
    req.session.regenerate((err: any) => {
      if (err) {
        console.error('❌ Session regeneration failed:', err);
        return res.status(500).json({ error: 'Session security error' });
      }
      
      // Restore session data after regeneration (prevents fixation attacks)
      Object.assign(req.session, originalSessionData);
      
      console.log('🔐 Session ID regenerated for security (login)');
      next();
    });
  } else {
    next();
  }
}

// Session regeneration for OAuth callbacks
export function oauthSessionRegenerationMiddleware(req: AuthRequest, res: Response, next: NextFunction) {
  if (req.path.includes('/auth/') && req.path.includes('/callback')) {
    const originalSessionData = { ...req.session };
    
    req.session.regenerate((err: any) => {
      if (err) {
        console.error('❌ OAuth session regeneration failed:', err);
        return next(); // Continue without regeneration rather than failing
      }
      
      // Restore session data after regeneration
      Object.assign(req.session, originalSessionData);
      
      console.log('🔐 Session ID regenerated for OAuth security');
      next();
    });
  } else {
    next();
  }
}