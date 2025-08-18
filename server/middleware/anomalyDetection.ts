/**
 * CRITICAL FIX: Anomaly Detection Middleware - HIGH SEVERITY
 * 
 * Problem: No centralized logging/detection for suspicious patterns
 * Solution: Comprehensive anomaly detection for stale sessions and suspicious access patterns
 */

import { Request, Response, NextFunction } from 'express';

interface SuspiciousPattern {
  pattern: string;
  severity: 'LOW' | 'MEDIUM' | 'HIGH';
  description: string;
}

export class AnomalyDetectionManager {
  private static instance: AnomalyDetectionManager;
  
  private suspiciousPatterns: SuspiciousPattern[] = [
    { pattern: '/admin', severity: 'HIGH', description: 'Admin panel access attempt' },
    { pattern: '/debug', severity: 'HIGH', description: 'Debug endpoint access attempt' },
    { pattern: '/.env', severity: 'HIGH', description: 'Environment file access attempt' },
    { pattern: '/config', severity: 'MEDIUM', description: 'Configuration file access attempt' },
    { pattern: '/api/auth', severity: 'MEDIUM', description: 'Authentication endpoint probing' },
    { pattern: '/wp-admin', severity: 'HIGH', description: 'WordPress admin attempt (wrong platform)' },
    { pattern: '/phpmyadmin', severity: 'HIGH', description: 'phpMyAdmin access attempt' },
    { pattern: '/.git', severity: 'HIGH', description: 'Git repository access attempt' },
    { pattern: '/backup', severity: 'MEDIUM', description: 'Backup file access attempt' },
    { pattern: '/test', severity: 'LOW', description: 'Test endpoint access' }
  ];

  private recentSessions: Map<string, {
    userId: number;
    lastActivity: number;
    requestCount: number;
    suspiciousActivity: number;
  }> = new Map();

  public static getInstance(): AnomalyDetectionManager {
    if (!AnomalyDetectionManager.instance) {
      AnomalyDetectionManager.instance = new AnomalyDetectionManager();
    }
    return AnomalyDetectionManager.instance;
  }

  /**
   * CRITICAL: Anomaly detection middleware
   */
  public detectAnomalies = (req: Request, res: Response, next: NextFunction): void => {
    const path = req.path.toLowerCase();
    const method = req.method;
    const userAgent = req.headers['user-agent'] || '';
    const ip = this.maskIP(req.ip || 'unknown');
    const sessionId = (req as any).session?.sessionId || 'anonymous';
    const userId = (req as any).session?.userId;

    // Check for suspicious patterns - only block exact admin/debug paths
    const suspiciousPattern = this.suspiciousPatterns.find(p => {
      const lowerPath = path.toLowerCase();
      const lowerPattern = p.pattern.toLowerCase();
      
      // More precise matching to avoid blocking legitimate routes
      if (lowerPattern === '/admin' || lowerPattern === '/debug') {
        return lowerPath === lowerPattern || lowerPath.startsWith(lowerPattern + '/');
      }
      return lowerPath.includes(lowerPattern);
    });

    if (suspiciousPattern) {
      console.warn(`🚨 [ANOMALY_${suspiciousPattern.severity}] Suspicious pattern detected:`, {
        pattern: suspiciousPattern.pattern,
        description: suspiciousPattern.description,
        path,
        method,
        ip,
        userAgent: this.maskUserAgent(userAgent),
        sessionId: sessionId.substring(0, 8) + '...',
        userId: userId || 'anonymous',
        timestamp: new Date().toISOString()
      });

      // Track suspicious activity
      if (sessionId !== 'anonymous') {
        this.trackSuspiciousActivity(sessionId, userId);
      }

      // Only block HIGH severity exact patterns
      if (suspiciousPattern.severity === 'HIGH' && 
          (path.toLowerCase() === suspiciousPattern.pattern.toLowerCase() ||
           path.toLowerCase().startsWith(suspiciousPattern.pattern.toLowerCase() + '/'))) {
        console.error(`🔒 [SECURITY_BLOCK] High-severity request blocked:`, {
          pattern: suspiciousPattern.pattern,
          ip,
          path,
          method,
          environment: process.env.NODE_ENV
        });
        
        res.status(403).json({
          error: 'Access denied',
          code: 'SUSPICIOUS_ACTIVITY_DETECTED',
          pattern: suspiciousPattern.pattern
        });
        return;
      }
    }

    // Track session activity
    if (userId && sessionId !== 'anonymous') {
      this.trackSessionActivity(sessionId, userId);
    }

    // Check for stale session anomalies
    this.detectStaleSessionAnomaly(req as any, res);

    next();
  };

  /**
   * Track suspicious activity for sessions
   */
  private trackSuspiciousActivity(sessionId: string, userId?: number): void {
    const session = this.recentSessions.get(sessionId) || {
      userId: userId || 0,
      lastActivity: Date.now(),
      requestCount: 0,
      suspiciousActivity: 0
    };

    session.suspiciousActivity++;
    session.lastActivity = Date.now();
    this.recentSessions.set(sessionId, session);

    // Alert on multiple suspicious activities
    if (session.suspiciousActivity >= 3) {
      console.error(`🚨 [ANOMALY_ALERT] Multiple suspicious activities detected:`, {
        sessionId: sessionId.substring(0, 8) + '...',
        userId: session.userId,
        suspiciousCount: session.suspiciousActivity,
        totalRequests: session.requestCount
      });
    }
  }

  /**
   * Track normal session activity
   */
  private trackSessionActivity(sessionId: string, userId: number): void {
    const session = this.recentSessions.get(sessionId) || {
      userId,
      lastActivity: Date.now(),
      requestCount: 0,
      suspiciousActivity: 0
    };

    session.requestCount++;
    session.lastActivity = Date.now();
    session.userId = userId;
    this.recentSessions.set(sessionId, session);

    // Clean old sessions (older than 1 hour)
    const oneHourAgo = Date.now() - (60 * 60 * 1000);
    for (const [id, sessionData] of this.recentSessions.entries()) {
      if (sessionData.lastActivity < oneHourAgo) {
        this.recentSessions.delete(id);
      }
    }
  }

  /**
   * Detect stale session anomalies
   */
  private detectStaleSessionAnomaly(req: any, res: Response): void {
    const userId = req.session?.userId;
    const sessionId = req.session?.sessionId;
    
    if (userId && sessionId) {
      const user = req.session.user;
      
      // Check for cancelled subscription with active session
      if (user?.subscriptionPlan === 'cancelled' && user?.subscriptionActive === false) {
        console.warn('🚨 [STALE_SESSION] Cancelled user attempting access:', {
          userId,
          sessionId: sessionId.substring(0, 8) + '...',
          subscriptionPlan: user.subscriptionPlan,
          path: req.path,
          timestamp: new Date().toISOString()
        });

        // Don't block immediately, but log for analysis
        if (req.path.includes('/api/cancel') || req.path.includes('/api/quota')) {
          console.log('📊 [STALE_SESSION] Potential UI state inconsistency detected');
        }
      }

      // Check session age
      const sessionAge = req.session.createdAt ? Date.now() - req.session.createdAt : 0;
      const maxAge = 24 * 60 * 60 * 1000; // 24 hours
      
      if (sessionAge > maxAge) {
        console.warn('🕐 [SESSION_EXPIRY] Stale session detected:', {
          userId,
          sessionAge: Math.round(sessionAge / (1000 * 60 * 60)) + 'h',
          maxAge: '24h',
          shouldExpire: true
        });
      }
    }
  }

  /**
   * Mask IP address for privacy (GDPR compliance)
   */
  private maskIP(ip: string): string {
    if (ip.includes(':')) {
      // IPv6
      const parts = ip.split(':');
      return parts.slice(0, 4).join(':') + '::****';
    } else {
      // IPv4
      const parts = ip.split('.');
      return parts.slice(0, 2).join('.') + '.***.*';
    }
  }

  /**
   * Mask user agent for privacy
   */
  private maskUserAgent(userAgent: string): string {
    return userAgent.substring(0, 50) + (userAgent.length > 50 ? '...' : '');
  }

  /**
   * Get anomaly statistics
   */
  public getAnomalyStats(): {
    totalSessions: number;
    suspiciousSessions: number;
    averageRequestsPerSession: number;
    patternsDetected: { [key: string]: number };
  } {
    const sessions = Array.from(this.recentSessions.values());
    const suspiciousSessions = sessions.filter(s => s.suspiciousActivity > 0);
    const totalRequests = sessions.reduce((sum, s) => sum + s.requestCount, 0);
    
    return {
      totalSessions: sessions.length,
      suspiciousSessions: suspiciousSessions.length,
      averageRequestsPerSession: sessions.length > 0 ? Math.round(totalRequests / sessions.length) : 0,
      patternsDetected: this.suspiciousPatterns.reduce((acc, pattern) => {
        acc[pattern.pattern] = 0; // Would need to track actual detections
        return acc;
      }, {} as { [key: string]: number })
    };
  }
}