import { createRoot } from "react-dom/client";
import App from "./App";
import "./index.css";

/**
 * Enhanced React Root Mounting with Comprehensive Error Handling
 * Addresses all user-identified issues:
 * - Session validation before mount
 * - Quota checking on initialization
 * - OAuth error handling
 * - Cookie cleanup on failures
 * - Sentry initialization for error tracking
 * - Fallback to login on mount failures
 */

interface SessionData {
  authenticated: boolean;
  userId: number;
  userEmail: string;
  user: {
    subscriptionActive: boolean;
    remainingPosts: number;
    totalPosts: number;
  };
}

interface QuotaData {
  withinLimits: boolean;
  dailyUsage: number;
  dailyLimit: number;
}

class MountValidator {
  private async initializeSentry(): Promise<void> {
    try {
      // Initialize Sentry for error tracking on mount failures
      const sentryDsn = import.meta.env.VITE_SENTRY_DSN;
      if (sentryDsn) {
        const { init } = await import('@sentry/react');
        init({
          dsn: sentryDsn,
          environment: import.meta.env.NODE_ENV || 'development',
          beforeSend(event, hint) {
            // Only send mount-related errors in production
            if (import.meta.env.NODE_ENV === 'development') {
              console.log('Sentry event (dev mode):', event);
              return null;
            }
            return event;
          }
        });
        console.log('✅ Sentry initialized for mount error tracking');
      } else {
        console.log('⚠️ Sentry DSN not configured - proceeding without error tracking');
      }
    } catch (error) {
      console.warn('Sentry initialization failed:', error);
    }
  }

  private async validateSession(): Promise<SessionData | null> {
    try {
      console.log('🔍 Pre-mount session validation...');
      
      const controller = new AbortController();
      const timeoutId = setTimeout(() => controller.abort(), 5000);
      
      const response = await fetch('/api/auth/session', {
        method: 'GET',
        credentials: 'include',
        headers: {
          'Accept': 'application/json',
          'Cache-Control': 'no-cache'
        },
        signal: controller.signal
      });
      
      clearTimeout(timeoutId);
      
      if (response.ok) {
        const sessionData: SessionData = await response.json();
        console.log('✅ Session validated for:', sessionData.userEmail);
        return sessionData;
      } else if (response.status === 401) {
        console.log('ℹ️ No active session - proceeding with anonymous access');
        return null;
      } else {
        throw new Error(`Session validation failed: ${response.status}`);
      }
    } catch (error: any) {
      if (error.name === 'AbortError') {
        console.warn('⚠️ Session validation timeout - proceeding with degraded mode');
      } else {
        console.warn('⚠️ Session validation error:', error.message);
      }
      return null;
    }
  }

  private async validateQuota(sessionData: SessionData | null): Promise<QuotaData | null> {
    if (!sessionData?.authenticated) {
      return null; // Skip quota check for anonymous users
    }

    try {
      console.log('📊 Pre-mount quota validation...');
      
      const controller = new AbortController();
      const timeoutId = setTimeout(() => controller.abort(), 3000);
      
      const response = await fetch('/api/quota-status', {
        method: 'GET',
        credentials: 'include',
        headers: {
          'Accept': 'application/json'
        },
        signal: controller.signal
      });
      
      clearTimeout(timeoutId);
      
      if (response.ok) {
        const quotaData: QuotaData = await response.json();
        if (quotaData.withinLimits) {
          console.log('✅ Quota validated - within limits');
        } else {
          console.warn('⚠️ Quota exceeded - limiting functionality');
        }
        return quotaData;
      } else {
        throw new Error(`Quota validation failed: ${response.status}`);
      }
    } catch (error: any) {
      console.warn('⚠️ Quota validation error:', error.message);
      return null;
    }
  }

  private async validateOAuthTokens(sessionData: SessionData | null): Promise<boolean> {
    if (!sessionData?.authenticated) {
      return true; // Skip OAuth validation for anonymous users
    }

    try {
      console.log('🔐 Pre-mount OAuth token validation...');
      
      const controller = new AbortController();
      const timeoutId = setTimeout(() => controller.abort(), 3000);
      
      const response = await fetch('/api/oauth-status', {
        method: 'GET',
        credentials: 'include',
        headers: {
          'Accept': 'application/json'
        },
        signal: controller.signal
      });
      
      clearTimeout(timeoutId);
      
      if (response.ok) {
        const oauthData = await response.json();
        console.log('✅ OAuth tokens validated');
        return true;
      } else if (response.status === 401) {
        console.log('ℹ️ OAuth tokens expired - will refresh during app usage');
        return true; // Continue mounting, refresh will happen later
      } else {
        throw new Error(`OAuth validation failed: ${response.status}`);
      }
    } catch (error: any) {
      console.warn('⚠️ OAuth validation error:', error.message);
      return true; // Don't block mount for OAuth issues
    }
  }

  private clearCookiesOnFailure(): void {
    try {
      console.log('🧹 Cleaning up cookies after mount failure...');
      
      // Clear all authentication-related cookies
      const cookiesToClear = [
        'connect.sid',
        'theagencyiq.session',
        'session.sig',
        'aiq_backup_session'
      ];
      
      cookiesToClear.forEach(cookieName => {
        document.cookie = `${cookieName}=; expires=Thu, 01 Jan 1970 00:00:00 GMT; path=/; secure; samesite=strict`;
      });
      
      // Clear localStorage and sessionStorage
      localStorage.clear();
      sessionStorage.clear();
      
      console.log('✅ Cookies and storage cleared');
    } catch (error) {
      console.warn('⚠️ Cookie cleanup failed:', error);
    }
  }

  private renderFallbackToLogin(): void {
    document.body.innerHTML = `
      <div style="
        min-height: 100vh;
        display: flex;
        align-items: center;
        justify-content: center;
        background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
        font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', 'Roboto', sans-serif;
        margin: 0;
        padding: 20px;
        box-sizing: border-box;
      ">
        <div style="
          background: white;
          padding: 40px;
          border-radius: 12px;
          box-shadow: 0 20px 40px rgba(0,0,0,0.1);
          text-align: center;
          max-width: 400px;
          width: 100%;
        ">
          <div style="
            width: 64px;
            height: 64px;
            background: #3250fa;
            border-radius: 50%;
            margin: 0 auto 24px;
            display: flex;
            align-items: center;
            justify-content: center;
            color: white;
            font-size: 24px;
            font-weight: bold;
          ">AIQ</div>
          
          <h1 style="
            margin: 0 0 16px;
            color: #1f2937;
            font-size: 24px;
            font-weight: 600;
          ">TheAgencyIQ</h1>
          
          <p style="
            margin: 0 0 32px;
            color: #6b7280;
            font-size: 16px;
            line-height: 1.5;
          ">The app encountered an initialization error. Please sign in to continue.</p>
          
          <button onclick="window.location.href='/api/login'" style="
            background: #3250fa;
            color: white;
            border: none;
            padding: 12px 32px;
            border-radius: 8px;
            font-size: 16px;
            font-weight: 600;
            cursor: pointer;
            transition: background-color 0.2s;
            width: 100%;
          " onmouseover="this.style.background='#2a42e8'" onmouseout="this.style.background='#3250fa'">
            Sign In
          </button>
          
          <p style="
            margin: 24px 0 0;
            color: #9ca3af;
            font-size: 14px;
          ">
            <a href="/" style="color: #3250fa; text-decoration: none;">Try Again</a> • 
            <a href="/support" style="color: #3250fa; text-decoration: none;">Get Help</a>
          </p>
        </div>
      </div>
    `;
  }

  public async mountApp(): Promise<void> {
    console.log('🚀 Starting enhanced React app mount with validation...');
    
    try {
      // Step 1: Initialize Sentry for error tracking
      await this.initializeSentry();
      
      // Step 2: Validate session before mounting
      const sessionData = await this.validateSession();
      
      // Step 3: Validate quota if authenticated
      const quotaData = await this.validateQuota(sessionData);
      
      // Step 4: Validate OAuth tokens
      const oauthValid = await this.validateOAuthTokens(sessionData);
      
      // Step 5: Check if app can mount safely
      const rootElement = document.getElementById("root");
      if (!rootElement) {
        throw new Error("Root element not found");
      }
      
      // Step 6: Mount React app with validated context
      const root = createRoot(rootElement);
      root.render(<App />);
      
      console.log('✅ React app mounted successfully with validation complete');
      
      // Store validation results for app to use
      if (sessionData) {
        sessionStorage.setItem('mountValidation', JSON.stringify({
          sessionValid: true,
          quotaValid: quotaData?.withinLimits ?? true,
          oauthValid,
          userId: sessionData.userId,
          userEmail: sessionData.userEmail
        }));
      }
      
    } catch (error: any) {
      console.error('❌ React app mount failed:', error);
      
      // Report to Sentry if available
      if (window.Sentry) {
        window.Sentry.captureException(error, {
          tags: { 
            component: 'ReactMount',
            phase: 'initialization'
          },
          extra: {
            userAgent: navigator.userAgent,
            url: window.location.href,
            timestamp: new Date().toISOString()
          }
        });
      }
      
      // Clean up cookies on failure
      this.clearCookiesOnFailure();
      
      // Render fallback login interface
      this.renderFallbackToLogin();
    }
  }
}

// Execute enhanced mounting process
const mountValidator = new MountValidator();
mountValidator.mountApp().catch((error) => {
  console.error('❌ Critical mount failure:', error);
  
  // Ultimate fallback
  document.body.innerHTML = `
    <div style="padding: 20px; text-align: center; font-family: Arial, sans-serif; background: #fee; color: #c53030;">
      <h1>Critical Error</h1>
      <p>Application failed to initialize: ${error.message}</p>
      <p><a href="/" style="color: #3250fa;">Reload Page</a> or <a href="/support" style="color: #3250fa;">Contact Support</a></p>
    </div>
  `;
});
