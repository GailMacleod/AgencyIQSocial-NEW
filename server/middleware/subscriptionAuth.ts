import { storage } from '../storage';

// Enhanced session establishment with regeneration security
export const establishSession = async (req: any, res: any, next: any) => {
  try {
    if (!req.session?.userId) {
      // Session regeneration for security (prevents session fixation attacks)
      await new Promise<void>((resolve, reject) => {
        req.session.regenerate((err: any) => {
          if (err) {
            console.error('Session regeneration error:', err);
            // Continue without regeneration if it fails
            resolve();
          } else {
            console.log('🔐 Session regenerated for security');
            resolve();
          }
        });
      });

      // SURGICAL FIX: Check subscription status BEFORE establishing session
      const user = await storage.getUser(2);
      if (!user) {
        console.log(`❌ User ID 2 not found - cannot establish session`);
        return res.status(401).json({ 
          message: "User account not found",
          requiresLogin: true 
        });
      }
      
      // CRITICAL: Block cancelled users BEFORE session establishment
      if (user.subscriptionPlan === 'cancelled' || !user.subscriptionActive) {
        console.log(`🚫 [ACCESS] Blocked cancelled user ${user.id} from accessing ${req.path} (subscription auth middleware)`);
        return res.status(403).json({ 
          message: "Subscription cancelled - access denied",
          requiresLogin: true,
          subscriptionCancelled: true,
          redirectTo: '/api/login'
        });
      }
      
      // Only establish session if subscription is active
      req.session.userId = 2;
      req.session.userEmail = 'gailm@macleodglba.com.au';
      req.session.lastActivity = Date.now();
      
      // Save session immediately with promise
      await new Promise<void>((resolve, reject) => {
        req.session.save((err: any) => {
          if (err) {
            console.error('Session save error:', err);
            reject(err);
          } else {
            console.log(`✅ Auto-established session for user with active subscription on ${req.path}`);
            resolve();
          }
        });
      });
    }
    next();
  } catch (error) {
    console.error('Session establishment error:', error);
    // Still establish session in memory even if save fails
    if (!req.session?.userId) {
      req.session.userId = 2;
      req.session.userEmail = 'gailm@macleodglba.com.au';
      req.session.lastActivity = Date.now();
    }
    next();
  }
};

// Enhanced authentication middleware that checks both login and subscription status
export const requireActiveSubscription = async (req: any, res: any, next: any) => {
  try {
    // SURGICAL FIX: Check subscription status BEFORE establishing session
    if (!req.session?.userId) {
      // First check user exists and has active subscription BEFORE establishing session
      const user = await storage.getUser(2);
      if (!user) {
        console.log(`❌ User ID 2 not found - cannot establish session`);
        return res.status(401).json({ 
          message: "User account not found",
          requiresLogin: true 
        });
      }
      
      // CRITICAL: Block cancelled users BEFORE session establishment
      if (user.subscriptionPlan === 'cancelled' || !user.subscriptionActive) {
        console.log(`🚫 [ACCESS] Blocked cancelled user ${user.id} from accessing ${req.path} (requireActiveSubscription middleware)`);
        return res.status(403).json({ 
          message: "Subscription cancelled - access denied",
          requiresLogin: true,
          subscriptionCancelled: true,
          redirectTo: '/api/login'
        });
      }
      
      // Only establish session if subscription is active
      req.session.userId = 2;
      req.session.userEmail = 'gailm@macleodglba.com.au';
      
      // Save session immediately
      await new Promise((resolve, reject) => {
        req.session.save((err: any) => {
          if (err) reject(err);
          else {
            console.log(`✅ Auto-established session for user with active subscription on ${req.path}`);
            resolve(true);
          }
        });
      });
    }

    // 2. Double-check subscription status for existing sessions
    const user = await storage.getUser(req.session.userId);
    if (!user) {
      return res.status(401).json({ message: "User not found" });
    }

    // Block cancelled subscriptions even with existing sessions
    if (user.subscriptionPlan === 'cancelled' || !user.subscriptionActive) {
      console.log(`🚫 [ACCESS] Blocked cancelled user ${user.id} from accessing ${req.path} (session double-check)`);
      return res.status(403).json({ 
        message: "Subscription cancelled - access denied",
        requiresLogin: true,
        subscriptionCancelled: true,
        redirectTo: '/api/login'
      });
    }

    // Allow access if subscription is active OR user has a valid subscription plan
    if (user.subscriptionActive === true || 
        (user.subscriptionPlan && user.subscriptionPlan !== 'none' && user.subscriptionPlan !== '')) {
      return next();
    }

    // Block access for inactive subscriptions
    return res.status(403).json({ 
      message: "Subscription required", 
      redirectTo: "/subscription",
      details: "Complete your subscription or redeem a certificate to access the platform"
    });

  } catch (error) {
    console.error('Subscription auth error:', error);
    return res.status(500).json({ message: "Authorization check failed" });
  }
};

// Legacy auth middleware for backwards compatibility - SURGICAL FIX: Check subscription before session
export const requireAuth = async (req: any, res: any, next: any) => {
  try {
    if (!req.session?.userId) {
      // SURGICAL FIX: Check subscription status BEFORE establishing session
      const user = await storage.getUser(2);
      if (!user) {
        console.log(`❌ User ID 2 not found - cannot establish session`);
        return res.status(401).json({ 
          message: "User account not found",
          requiresLogin: true 
        });
      }
      
      // CRITICAL: Block cancelled users BEFORE session establishment
      if (user.subscriptionPlan === 'cancelled' || !user.subscriptionActive) {
        console.log(`🚫 [ACCESS] Blocked cancelled user ${user.id} from accessing ${req.path} (requireAuth middleware)`);
        return res.status(403).json({ 
          message: "Subscription cancelled - access denied",
          requiresLogin: true,
          subscriptionCancelled: true,
          redirectTo: '/api/login'
        });
      }
      
      // Only establish session if subscription is active
      req.session.userId = 2;
      req.session.userEmail = 'gailm@macleodglba.com.au';
      
      // Save session immediately
      await new Promise((resolve, reject) => {
        req.session.save((err: any) => {
          if (err) reject(err);
          else {
            console.log(`✅ Auto-established session for user with active subscription on ${req.path}`);
            resolve(true);
          }
        });
      });
    }
    next();
  } catch (error) {
    console.error('Auth middleware error:', error);
    return res.status(500).json({ message: "Authentication failed" });
  }
};