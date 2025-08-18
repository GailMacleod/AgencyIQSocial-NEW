// Session Validation Utility
// Provides session validation for both HTTP requests and script operations

const { logger } = require('./logger.js');

class SessionValidator {
  constructor() {
    this.validSessions = new Map();
    this.sessionTimeout = 3 * 24 * 60 * 60 * 1000; // 3 days in milliseconds
  }

  // Validate session ID format
  isValidSessionFormat(sessionId) {
    if (!sessionId || typeof sessionId !== 'string') {
      return false;
    }

    // Session must start with 'aiq_' and have proper format
    const sessionPattern = /^aiq_[a-z0-9]+_[a-z0-9]+$/;
    return sessionPattern.test(sessionId);
  }

  // Extract session ID from cookie string
  extractSessionFromCookie(cookieString) {
    if (!cookieString) return null;

    // Look for theagencyiq.session cookie
    const sessionMatch = cookieString.match(/theagencyiq\.session=([^;]+)/);
    if (!sessionMatch) return null;

    let sessionId = sessionMatch[1];
    
    // Handle URL encoding
    sessionId = decodeURIComponent(sessionId);
    
    // Remove 's:' prefix if present (express-session format)
    if (sessionId.startsWith('s:')) {
      sessionId = sessionId.split('.')[0].substring(2);
    }

    return sessionId;
  }

  // Validate session for HTTP requests
  validateHTTPSession(req) {
    const sessionId = req.sessionID;
    const userId = req.session?.userId;
    const cookieSessionId = this.extractSessionFromCookie(req.headers.cookie);

    // Check session ID format
    if (!this.isValidSessionFormat(sessionId)) {
      logger.security('Invalid session format in HTTP request', {
        sessionId: sessionId?.substring(0, 10) + '...',
        path: req.path,
        ip: req.ip
      });
      return false;
    }

    // Check user ID presence
    if (!userId) {
      logger.security('Missing user ID in session', {
        sessionId: sessionId.substring(0, 10) + '...',
        path: req.path,
        ip: req.ip
      });
      return false;
    }

    // Validate cookie consistency
    if (cookieSessionId && cookieSessionId !== sessionId) {
      logger.security('Session ID mismatch between server and cookie', {
        serverSessionId: sessionId.substring(0, 10) + '...',
        cookieSessionId: cookieSessionId.substring(0, 10) + '...',
        path: req.path,
        ip: req.ip
      });
      return false;
    }

    logger.info('HTTP session validation passed', {
      userId,
      sessionId: sessionId.substring(0, 10) + '...',
      path: req.path
    });

    return true;
  }

  // Validate session for script operations
  validateScriptSession(sessionCookie, userId) {
    if (!sessionCookie || !userId) {
      logger.security('Missing session cookie or user ID for script operation', {
        hasSessionCookie: !!sessionCookie,
        hasUserId: !!userId
      });
      return false;
    }

    const sessionId = this.extractSessionFromCookie(sessionCookie);
    if (!sessionId) {
      logger.security('Unable to extract session ID from cookie for script', {
        cookieFormat: sessionCookie.substring(0, 30) + '...'
      });
      return false;
    }

    if (!this.isValidSessionFormat(sessionId)) {
      logger.security('Invalid session format for script operation', {
        sessionId: sessionId.substring(0, 10) + '...',
        userId
      });
      return false;
    }

    logger.info('Script session validation passed', {
      userId,
      sessionId: sessionId.substring(0, 10) + '...',
      timestamp: new Date().toISOString()
    });

    return true;
  }

  // Create middleware for session validation
  createValidationMiddleware() {
    return (req, res, next) => {
      if (!this.validateHTTPSession(req)) {
        return res.status(401).json({
          error: 'Session validation failed',
          code: 'INVALID_SESSION',
          message: 'Valid session required for this operation',
          timestamp: new Date().toISOString()
        });
      }
      next();
    };
  }

  // Validate session for database operations
  validateDatabaseAccess(sessionId, userId, operation) {
    if (!this.isValidSessionFormat(sessionId)) {
      logger.security('Invalid session for database access', {
        sessionId: sessionId?.substring(0, 10) + '...',
        userId,
        operation
      });
      return false;
    }

    if (!userId) {
      logger.security('Missing user ID for database access', {
        sessionId: sessionId.substring(0, 10) + '...',
        operation
      });
      return false;
    }

    logger.info('Database access validated', {
      userId,
      sessionId: sessionId.substring(0, 10) + '...',
      operation
    });

    return true;
  }
}

// Singleton instance
const sessionValidator = new SessionValidator();

module.exports = {
  SessionValidator,
  sessionValidator
};