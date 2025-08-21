// main.tsx - Refactored React root mounting with enhanced validation and error handling
// Filename: main.tsx

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
      const sentryDsn = import.meta.env.VITE_SENTRY_DSN;
      if (sentryDsn) {
        const { init } = await import('./utils/sentry-config.ts');
        init({
          dsn: sentryDsn,
          environment: import.meta.env.MODE || 'development',
          beforeSend: (event, hint) => {
            if (import.meta.env.MODE === 'development') {
              console.log('Sentry event (dev mode):', event);
              return null;
            }
            return event;
          }
        });
      }
    } catch (error) {
      console.warn('Sentry initialization failed:', error);
    }
  }

  private async validateSession(): Promise<SessionData | null> {
    try {
      const response = await fetch('/api/auth/session', {
        method: 'GET',
        credentials: 'include',
        headers: {
          'Accept': 'application/json',
          'Cache-Control': 'no-cache'
        },
      });

      if (response.ok) {
        return await response.json() as SessionData;
      } else if (response.status === 401) {
        return null;
      } else {
        throw new Error(`Session validation failed: ${response.status}`);
      }
    } catch (error) {
      console.warn('Session validation error:', error);
      return null;
    }
  }

  private async validateQuota(sessionData: SessionData | null): Promise<QuotaData | null> {
    if (!sessionData?.authenticated) return null;

    try {
      const response = await fetch('/api/quota-status', {
        method: 'GET',
        credentials: 'include',
        headers: {
          'Accept': 'application/json'
        },
      });

      if (response.ok) {
        return await response.json() as QuotaData;
      } else {
        throw new Error(`Quota validation failed: ${response.status}`);
      }
    } catch (error) {
      console.warn('Quota validation error:', error);
      return null;
    }
  }

  private async validateOAuthTokens(sessionData: SessionData | null): Promise<boolean> {
    if (!sessionData?.authenticated) return true;

    try {
      const response = await fetch('/api/oauth-status', {
        method: 'GET',
        credentials: 'include',
        headers: {
          'Accept': 'application/json'
        },
      });

      return response.ok;
    } catch (error) {
      console.warn('OAuth validation error:', error);
      return true; // Don't block mount
    }
  }

  private clearCookiesOnFailure(): void {
    const cookiesToClear = [
      'connect.sid',
      'theagencyiq.session',
      'session.sig',
      'aiq_backup_session'
    ];

    cookiesToClear.forEach(cookieName => {
      document.cookie = `${cookieName}=; expires=Thu, 01 Jan 1970 00:00:00 GMT; path=/; secure; samesite=strict`;
    });

    localStorage.clear();
    sessionStorage.clear();
  }

  private renderFallbackToLogin(errorMessage: string): void {
    document.body.innerHTML = `
      <div style="display: flex; align-items: center; justify-content: center; min-height: 100vh; background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; color: #1f2937; padding: 20px; box-sizing: border-box;">
        <div style="background: white; padding: 40px; border-radius: 12px; box-shadow: 0 20px 40px rgba(0,0,0,0.1); text-align: center; max-width: 400px; width: 100%;">
          <div style="width: 64px; height: 64px; background: #3250fa; border-radius: 50%; margin: 0 auto 24px; display: flex; align-items: center; justify-content: center; color: white; font-size: 24px; font-weight: bold;">AIQ</div>
          <h1 style="margin: 0 0 16px; font-size: 24px; font-weight: 600;">Initialization Error</h1>
          <p style="margin: 0 0 16px; color: #6b7280; font-size: 16px; line-height: 1.5;">${errorMessage}</p>
          <p style="margin: 0 0 32px; color: #6b7280; font-size: 16px; line-height: 1.5;">Please sign in to continue.</p>
          <button onclick="window.location.href='/login'" style="background: #3250fa; color: white; border: none; padding: 12px 32px; border-radius: 8px; font-size: 16px; font-weight: 600; cursor: pointer; transition: background 0.2s; width: 100%;">Sign In</button>
          <p style="margin: 24px 0 0; color: #9ca3af; font-size: 14px;"><a href="/" style="color: #3250fa; text-decoration: none;">Try Again</a> • <a href="/support" style="color: #3250fa; text-decoration: none;">Get Help</a></p>
        </div>
      </div>
    `;
  }

  public async mountApp(): Promise<void> {
    try {
      await this.initializeSentry();
      const sessionData = await this.validateSession();
      const quotaData = await this.validateQuota(sessionData);
      const oauthValid = await this.validateOAuthTokens(sessionData);

      const rootElement = document.getElementById("root");
      if (!rootElement) throw new Error("Root element not found");

      const root = createRoot(rootElement);
      root.render(<App />);

      if (sessionData) {
        sessionStorage.setItem('mountValidation', JSON.stringify({
          sessionValid: true,
          quotaValid: quotaData?.withinLimits ?? true,
          oauthValid,
          userId: sessionData.userId,
          userEmail: sessionData.userEmail
        }));
      }
    } catch (error) {
      const errorMessage = error instanceof Error ? error.message : 'Unknown error occurred';
      console.error('App mount failed:', errorMessage);
      if (window.Sentry) {
        window.Sentry.captureException(error, {
          tags: { component: 'ReactMount', phase: 'initialization' },
          extra: { userAgent: navigator.userAgent, url: window.location.href }
        });
      }
      this.clearCookiesOnFailure();
      this.renderFallbackToLogin(errorMessage);
    }
  }
}

const mountValidator = new MountValidator();
mountValidator.mountApp();
