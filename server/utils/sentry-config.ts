// Server-side Sentry shim to disable real integration and prevent crashes.
// Mocks key methods with console logs in dev mode.

type Level = 'fatal' | 'error' | 'warning' | 'log' | 'info' | 'debug';
type CaptureContext = Record<string, unknown>;

type SentryShim = {
  captureException: (error: Error, context?: CaptureContext) => void;
  captureMessage: (message: string, level?: Level) => void;
  setUser: (user: Record<string, unknown> | null) => void;
  setTag: (key: string, value: string) => void;
  setContext: (key: string, context: CaptureContext | null) => void;
  addBreadcrumb: (breadcrumb: CaptureContext) => void;
  configureScope: (cb: (scope: unknown) => void) => void;
};

const devLog = (...args: unknown[]) => {
  if (process.env.NODE_ENV === 'development') {
    console.log('[Sentry server shim]', ...args);
  }
};

const shim: SentryShim = {
  captureException(error, context) {
    devLog('captureException', error, context);
  },
  captureMessage(message, level) {
    devLog('captureMessage', message, level);
  },
  setUser(user) {
    devLog('setUser', user);
  },
  setTag(key, value) {
    devLog('setTag', key, value);
  },
  setContext(key, context) {
    devLog('setContext', key, context);
  },
  addBreadcrumb(breadcrumb) {
    devLog('addBreadcrumb', breadcrumb);
  },
  configureScope(cb) {
    devLog('configureScope');
    try { cb({}); } catch { /* ignore */ }
  },
};

export function initSentry(): void {
  (global as any).Sentry = shim;
}

// Auto-initialize
initSentry();

// Optional exports for direct use
export const captureException = (error: unknown, context?: CaptureContext) =>
  (global as any).Sentry?.captureException(error as Error, context);

export const captureMessage = (message: string, level?: Level) =>
  (global as any).Sentry?.captureMessage(message, level);