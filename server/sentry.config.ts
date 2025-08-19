import * as Sentry from '@sentry/react';

export interface Sentry {
  captureException: (error: Error, context?: any) => string;
  captureMessage: (message: string, level?: string) => string;
  setUser: (user: any) => void;
  setTag: (key: string, value: string) => void;
  setContext: (key: string, context: any) => void;
  addBreadcrumb: (breadcrumb: any) => void;
  configureScope: (callback: (scope: any) => void) => void;
}

// Init Sentry if env set
if (process.env.NODE_ENV === 'production') {
  Sentry.init({
    dsn: process.env.VITE_SENTRY_DSN,
    // Other config...
  });
}