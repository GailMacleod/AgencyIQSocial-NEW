/**
 * Sentry Configuration for Error Tracking and Logging
 * Provides comprehensive error reporting with user context
 */

// Extend Window interface for Sentry
declare global {
  interface Window {
    Sentry?: {
      init: (config: any) => void;
      captureException: (error: Error, context?: any) => string;
      captureMessage: (message: string, level?: string) => string;
      setUser: (user: any) => void;
      setTag: (key: string, value: string) => void;
      setContext: (key: string, context: any) => void;
      addBreadcrumb: (breadcrumb: any) => void;
      configureScope: (callback: (scope: any) => void) => void;
    };
  }
}

interface SentryConfig {
  dsn?: string;
  environment: string;
  sampleRate: number;
  beforeSend?: (event: any) => any;
  integrations?: any[];
}

class SentryLogger {
  private isInitialized = false;
  private pendingEvents: Array<() => void> = [];

  public async initialize() {
    try {
      // Skip initialization in development unless explicitly enabled
      if (process.env.NODE_ENV === 'development' && !import.meta.env.VITE_SENTRY_ENABLE_DEV) {
        console.log('Sentry disabled in development mode');
        return;
      }

      const dsn = import.meta.env.VITE_SENTRY_DSN;
      
      if (!dsn) {
        console.warn('Sentry DSN not configured - error tracking disabled');
        return;
      }

      // Dynamically import Sentry to avoid bundle size impact when not needed
      const { init, captureException, captureMessage, setUser, setTag, setContext, addBreadcrumb } = await import('@sentry/react');
      
      // Attach to window for global access
      window.Sentry = {
        init,
        captureException,
        captureMessage,
        setUser,
        setTag,
        setContext,
        addBreadcrumb,
        configureScope: () => {} // Placeholder for compatibility
      };

      const config: SentryConfig = {
        dsn,
        environment: process.env.NODE_ENV || 'development',
        sampleRate: process.env.NODE_ENV === 'production' ? 0.1 : 1.0,
        beforeSend: (event) => {
          // Filter out development errors and sensitive data
          if (process.env.NODE_ENV === 'development' && !import.meta.env.VITE_SENTRY_ENABLE_DEV) {
            return null;
          }
          
          // Remove sensitive information
          if (event.request?.cookies) {
            delete event.request.cookies;
          }
          
          if (event.request?.headers?.authorization) {
            delete event.request.headers.authorization;
          }
          
          return event;
        }
      };

      init(config);
      
      // Set initial context
      setTag('component', 'TheAgencyIQ');
      setContext('app', {
        name: 'TheAgencyIQ',
        version: '1.0.0',
        build: Date.now()
      });

      this.isInitialized = true;
      console.log('✅ Sentry initialized successfully');
      
      // Process any pending events
      this.pendingEvents.forEach(event => event());
      this.pendingEvents = [];

    } catch (error) {
      console.error('❌ Sentry initialization failed:', error);
      // Don't break the app if Sentry fails to initialize
    }
  }

  public captureException(error: Error, context?: any): string | null {
    if (!this.isInitialized || !window.Sentry) {
      // Queue for later if not initialized yet
      this.pendingEvents.push(() => this.captureException(error, context));
      console.error('Error (Sentry not ready):', error);
      return null;
    }

    try {
      const eventId = window.Sentry.captureException(error, {
        tags: {
          component: context?.component || 'unknown',
          feature: context?.feature || 'unknown'
        },
        extra: {
          timestamp: new Date().toISOString(),
          userAgent: navigator.userAgent,
          url: window.location.href,
          ...context?.extra
        },
        level: context?.level || 'error'
      });

      console.error('Error captured by Sentry:', eventId, error);
      return eventId;
    } catch (sentryError) {
      console.error('Failed to capture error with Sentry:', sentryError);
      console.error('Original error:', error);
      return null;
    }
  }

  public captureMessage(message: string, level: 'info' | 'warning' | 'error' = 'info', context?: any): string | null {
    if (!this.isInitialized || !window.Sentry) {
      this.pendingEvents.push(() => this.captureMessage(message, level, context));
      console.log(`Message (Sentry not ready): ${message}`);
      return null;
    }

    try {
      return window.Sentry.captureMessage(message, level as any);
    } catch (error) {
      console.error('Failed to capture message with Sentry:', error);
      return null;
    }
  }

  public setUser(user: { id?: string; email?: string; username?: string }) {
    if (!this.isInitialized || !window.Sentry) {
      this.pendingEvents.push(() => this.setUser(user));
      return;
    }

    try {
      window.Sentry.setUser({
        id: user.id,
        email: user.email,
        username: user.username
      });
    } catch (error) {
      console.error('Failed to set Sentry user:', error);
    }
  }

  public addBreadcrumb(message: string, category: string = 'custom', level: string = 'info', data?: any) {
    if (!this.isInitialized || !window.Sentry) {
      this.pendingEvents.push(() => this.addBreadcrumb(message, category, level, data));
      return;
    }

    try {
      window.Sentry.addBreadcrumb({
        message,
        category,
        level,
        timestamp: Date.now() / 1000,
        data
      });
    } catch (error) {
      console.error('Failed to add Sentry breadcrumb:', error);
    }
  }

  public setContext(key: string, context: any) {
    if (!this.isInitialized || !window.Sentry) {
      this.pendingEvents.push(() => this.setContext(key, context));
      return;
    }

    try {
      window.Sentry.setContext(key, context);
    } catch (error) {
      console.error('Failed to set Sentry context:', error);
    }
  }

  public isReady(): boolean {
    return this.isInitialized && !!window.Sentry;
  }
}

// Export singleton instance
export const sentryLogger = new SentryLogger();

// Convenience functions
export const captureError = (error: Error, context?: any) => 
  sentryLogger.captureException(error, context);

export const captureMessage = (message: string, level?: 'info' | 'warning' | 'error', context?: any) => 
  sentryLogger.captureMessage(message, level, context);

export const setUser = (user: { id?: string; email?: string; username?: string }) => 
  sentryLogger.setUser(user);

export const addBreadcrumb = (message: string, category?: string, level?: string, data?: any) => 
  sentryLogger.addBreadcrumb(message, category, level, data);

export const setContext = (key: string, context: any) => 
  sentryLogger.setContext(key, context);

// React error boundary hook
export function useErrorHandler() {
  return {
    captureError,
    captureMessage,
    addBreadcrumb: (message: string, data?: any) => addBreadcrumb(message, 'user-action', 'info', data)
  };
}

// Global error handlers
export function setupGlobalErrorHandlers() {
  // Unhandled promise rejections
  window.addEventListener('unhandledrejection', (event) => {
    console.error('Unhandled promise rejection:', event.reason);
    captureError(new Error(`Unhandled promise rejection: ${event.reason}`), {
      component: 'Global',
      feature: 'PromiseRejection',
      extra: { reason: event.reason }
    });
  });

  // Global errors
  window.addEventListener('error', (event) => {
    console.error('Global error:', event.error);
    captureError(event.error || new Error(event.message), {
      component: 'Global',
      feature: 'JavaScriptError',
      extra: {
        filename: event.filename,
        lineno: event.lineno,
        colno: event.colno
      }
    });
  });

  console.log('✅ Global error handlers configured');
}