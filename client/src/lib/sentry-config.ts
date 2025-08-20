// Sentry is disabled to keep costs down.
// This file provides a lightweight shim so calls like
// window.Sentry.captureException(error, { tags: {...} }) won't crash.

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

type SentryWindow = Window & { Sentry?: SentryShim };

const devLog = (...args: unknown[]) => {
  if (import.meta.env.DEV) {
    // eslint-disable-next-line no-console
    console.log('[Sentry shim]', ...args);
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
  (window as SentryWindow).Sentry = shim;
}

// Auto‑initialize so window.Sentry is always defined if this file is imported.
initSentry();

// Optional convenience exports if you prefer calling functions instead of window.Sentry.*
export const captureException = (error: unknown, context?: CaptureContext) =>
  (window as SentryWindow).Sentry?.captureException(error as Error, context);

export const captureMessage = (message: string, level?: Level) =>
  (window as SentryWindow).Sentry?.captureMessage(message, level);
