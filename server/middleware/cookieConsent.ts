/**
 * CRITICAL: 2025 ePrivacy Compliance Middleware - HIGH SEVERITY FIX
 * 
 * Problem: No consent mechanism = GDPR fines
 * Solution: Comprehensive consent management with granular preferences
 */

import { Request, Response, NextFunction } from 'express';

interface ConsentPreferences {
  essential: boolean;
  analytics: boolean;
  marketing: boolean;
  timestamp: number;
}

export class CookieConsentManager {
  private static instance: CookieConsentManager;

  public static getInstance(): CookieConsentManager {
    if (!CookieConsentManager.instance) {
      CookieConsentManager.instance = new CookieConsentManager();
    }
    return CookieConsentManager.instance;
  }

  /**
   * Check if user has given required consent
   */
  public hasConsent(req: Request, consentType: 'essential' | 'analytics' | 'marketing' = 'essential'): boolean {
    try {
      const consentCookie = req.cookies['cookie-consent'];
      if (!consentCookie) return false;

      const consent: ConsentPreferences = JSON.parse(decodeURIComponent(consentCookie));
      return consent[consentType] === true;
    } catch (error) {
      return false;
    }
  }

  /**
   * Set consent preferences
   */
  public setConsent(res: Response, preferences: Partial<ConsentPreferences>): void {
    const consent: ConsentPreferences = {
      essential: true, // Always required
      analytics: preferences.analytics || false,
      marketing: preferences.marketing || false,
      timestamp: Date.now()
    };

    res.cookie('cookie-consent', JSON.stringify(consent), {
      maxAge: 365 * 24 * 60 * 60 * 1000, // 1 year
      httpOnly: false, // Needs to be accessible to frontend
      secure: process.env.NODE_ENV === 'production',
      sameSite: 'strict',
      partitioned: true
    });

    console.log('✅ [CONSENT] Cookie consent preferences saved:', {
      essential: consent.essential,
      analytics: consent.analytics,
      marketing: consent.marketing
    });
  }

  /**
   * Revoke all consent
   */
  public revokeConsent(res: Response): void {
    res.clearCookie('cookie-consent');
    res.clearCookie('theagencyiq.session');
    res.clearCookie('aiq_backup_session');
    
    console.log('🔄 [CONSENT] All cookies revoked due to consent withdrawal');
  }
}

/**
 * CRITICAL: Consent enforcement middleware (2025 GDPR requirement)
 */
export const requireConsent = (consentType: 'essential' | 'analytics' | 'marketing' = 'essential') => {
  return (req: Request, res: Response, next: NextFunction): void => {
    // Skip consent check for consent-related endpoints
    if (req.path.includes('/consent') || req.path.includes('/api/login')) {
      return next();
    }

    const consentManager = CookieConsentManager.getInstance();
    
    if (!consentManager.hasConsent(req, consentType)) {
      // Set consent required flag for frontend
      res.cookie('consent-required', '1', { 
        maxAge: 5 * 60 * 1000, // 5 minutes
        httpOnly: false,
        secure: process.env.NODE_ENV === 'production',
        sameSite: 'strict'
      });

      if (req.path.startsWith('/api/')) {
        return res.status(403).json({ 
          error: 'Consent required',
          consentType,
          message: `${consentType} consent is required to access this resource`
        });
      }
    }

    next();
  };
};

/**
 * Consent management endpoints
 */
export const setupConsentRoutes = (app: any): void => {
  // Set consent preferences
  app.post('/api/consent', (req: Request, res: Response) => {
    try {
      const { analytics, marketing } = req.body;
      const consentManager = CookieConsentManager.getInstance();
      
      consentManager.setConsent(res, { analytics, marketing });
      
      res.json({ 
        success: true, 
        message: 'Consent preferences saved',
        preferences: { essential: true, analytics, marketing }
      });
    } catch (error: any) {
      res.status(400).json({ error: 'Invalid consent data', message: error.message });
    }
  });

  // Revoke consent
  app.delete('/api/consent', (req: Request, res: Response) => {
    const consentManager = CookieConsentManager.getInstance();
    consentManager.revokeConsent(res);
    
    res.json({ 
      success: true, 
      message: 'All consent revoked and cookies cleared' 
    });
  });

  // Get current consent status
  app.get('/api/consent', (req: Request, res: Response) => {
    const consentManager = CookieConsentManager.getInstance();
    
    res.json({
      essential: consentManager.hasConsent(req, 'essential'),
      analytics: consentManager.hasConsent(req, 'analytics'),
      marketing: consentManager.hasConsent(req, 'marketing'),
      hasAnyConsent: consentManager.hasConsent(req, 'essential')
    });
  });
};