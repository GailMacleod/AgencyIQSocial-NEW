// client/src/types/global.d.ts
// Keep this as the ONLY place that declares window.Sentry.

type SentryLevel = 'fatal' | 'error' | 'warning' | 'log' | 'info' | 'debug';
type SentryContext = Record<string, unknown>;

declare global {
  interface Window {
    Sentry?: {
      captureException: (error: Error, context?: SentryContext) => void;
      captureMessage: (message: string, level?: SentryLevel) => void;
      setUser: (user: Record<string, unknown> | null) => void;
      setTag: (key: string, value: string) => void;
      setContext: (key: string, context: SentryContext | null) => void;
      addBreadcrumb: (breadcrumb: SentryContext) => void;
      configureScope: (cb: (scope: unknown) => void) => void;
    };

    // Common project globals you referenced elsewhere:
    dataLayer?: any[];
    gtag?: (...args: any[]) => void;
    queryClient?: unknown;
  }

  interface Navigator {
    standalone?: boolean; // for iOS PWA checks
  }
}

export {};
