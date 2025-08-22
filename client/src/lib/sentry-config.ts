// Sentry is disabled to keep costs down.
// Lightweight shim so calls like window.Sentry.captureException(...) won't crash.

declare global {
  interface Window {
    Sentry?: SentryShim;
  }
}

type Level = 'fatal' | 'error' | 'warning' | 'log' | 'info' | 'debug';
type CaptureContext = Record<string, unknown>;

interface SentryShim {
  captureException: (_error: unknown, _context?: CaptureContext) => void;
  captureMessage: (_message: string, _level?: Level) => void;
  setUser: (_user: Record<string, unknown> | null) => void;
  setTag: (_key: string, _value: string) => void;
  setContext: (_key: string, _context: CaptureContext | null) => void;
  addBreadcrumb: (_breadcrumb: CaptureContext) => void;
  configureScope: (_cb: (_scope: unknown) => void) => void;
}

const devLog = (...args: unknown[]) => {
  if (import.meta.env.DEV) {
    console.log('[Sentry shim]', ...args);
  }
};

const shim: SentryShim = {
  captureException(_error, _context) {
    devLog('captureException', _error, _context);
  },
  captureMessage(_message, _level) {
    devLog('captureMessage', _message, _level);
  },
  setUser(_user) {
    devLog('setUser', _user);
  },
  setTag(_key, _value) {
    devLog('setTag', _key, _value);
  },
  setContext(_key, _context) {
    devLog('setContext', _key, _context);
  },
  addBreadcrumb(_breadcrumb) {
    devLog('addBreadcrumb', _breadcrumb);
  },
  configureScope(_cb) {
    devLog('configureScope');
    try { _cb({}); } catch { /* ignore */ }
  },
};

export function initSentry(): void {
  window.Sentry = shim;
}

// Auto-initialize so window.Sentry is always defined if this file is imported.
initSentry();

// Convenience exports for files that import helpers
export const captureException = (_error: unknown, _context?: CaptureContext) =>
  window.Sentry?.captureException(_error, _context);

export const captureMessage = (_message: string, _level?: Level) =>
  window.Sentry?.captureMessage(_message, _level);

// For components importing these:
export const sentryLogger = {
  error: (_error: unknown, _context?: CaptureContext) => captureException(_error, _context),
  info: (_message: string | unknown, _extra?: CaptureContext) =>
    captureMessage(typeof _message === 'string' ? _message : String(_message), 'info'),
};

let handlersInstalled = false;
export function setupGlobalErrorHandlers(): void {
  if (handlersInstalled) return;
  handlersInstalled = true;

  window.addEventListener('error', (ev) => {
    const ee = ev as ErrorEvent;
    const err = ee.error ?? new Error(ee.message || 'Unknown error');
    captureException(err, {
      tags: { component: 'window.error' },
      extra: { href: window.location.href },
    });
  });

  window.addEventListener('unhandledrejection', (ev) => {
    const pre = ev as PromiseRejectionEvent;
    const reason = pre.reason;
    captureException(reason instanceof Error ? reason : new Error(String(reason) || 'Unhandled rejection'), {
      tags: { component: 'unhandledrejection' },
      extra: { href: window.location.href, reason },
    });
  });
}