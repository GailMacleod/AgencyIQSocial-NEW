// client/src/lib/sentry-config.ts
// -----------------------------------------------------------------------------
// Zero-cost Sentry shim so calls like
//   window.Sentry.captureException(error, { tags: {...}, extra: {...} })
//   sentryLogger.error(err, { ... })
//   setupGlobalErrorHandlers()
// all work without pulling the Sentry SDK.
// -----------------------------------------------------------------------------

// NOTE: This file intentionally does NOT declare `window.Sentry` globally.
// Keep the single global type declaration in: client/src/types/global.d.ts

type Level = 'fatal' | 'error' | 'warning' | 'log' | 'info' | 'debug';

export type SentryContext = {
  tags?: Record<string, string>;
  extra?: Record<string, unknown>;
};

type SentryShim = {
  captureException: (error: Error, context?: SentryContext) => void;
  captureMessage: (message: string, level?: Level) => void;
  setUser: (user: Record<string, unknown> | null) => void;
  setTag: (key: string, value: string) => void;
  setContext: (key: string, context: Record<string, unknown> | null) => void;
  addBreadcrumb: (breadcrumb: Record<string, unknown>) => void;
  configureScope: (cb: (scope: unknown) => void) => void;
};

type SentryWindow = Window & { Sentry?: SentryShim };

const isDev =
  typeof import.meta !== 'undefined' && !!(import.meta as any).env?.DEV;

const devLog = (...args: unknown[]) => {
  if (isDev) {
    // eslint-disable-next-line no-console
    console.log('[SentryShim]', ...args);
  }
};

const shim: SentryShim = {
  captureException(error, context) {
    devLog('captureException', error, context ?? {});
  },
  captureMessage(message, level) {
    devLog('captureMessage', { message, level: level ?? 'info' });
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
    try {
      cb({});
    } catch {
      /* ignore */
    }
  },
};

// Install the shim once (idempotent).
export function initSentry(): void {
  const win = window as SentryWindow;
  if (!win.Sentry) win.Sentry = shim;
}
initSentry();

// -----------------------------------------------------------------------------
// Convenience wrappers that other parts of the app import
// -----------------------------------------------------------------------------

export const captureException = (error: unknown, context?: SentryContext) => {
  const err = error instanceof Error ? error : new Error(String(error));
  (window as SentryWindow).Sentry?.captureException(err, context);
};

export const captureMessage = (message: string, level?: Level) =>
  (window as SentryWindow).Sentry?.captureMessage(message, level);

export const setUser = (user: Record<string, unknown> | null) =>
  (window as SentryWindow).Sentry?.setUser(user);

export const setTag = (key: string, value: string) =>
  (window as SentryWindow).Sentry?.setTag(key, value);

export const setContext = (key: string, ctx: Record<string, unknown> | null) =>
  (window as SentryWindow).Sentry?.setContext(key, ctx);

// Logger object some files expect
export const sentryLogger = {
  error: (error: unknown, context?: SentryContext) => captureException(error, context),
  info: (message: string | unknown) =>
    captureMessage(typeof message === 'string' ? message : String(message), 'info'),
};

// Global error handlers some files call at startup
let handlersInstalled = false;
export function setupGlobalErrorHandlers(): void {
  if (handlersInstalled) return;
  handlersInstalled = true;

  window.addEventListener('error', (ev) => {
    const ee = ev as ErrorEvent;
    const err =
      ee?.error instanceof Error
        ? ee.error
        : new Error(ee?.message || 'Unknown error');
    captureException(err, {
      tags: { component: 'window.error' },
      extra: { href: window.location.href },
    });
  });

  window.addEventListener('unhandledrejection', (ev) => {
    const pre = ev as PromiseRejectionEvent;
    const reason = pre?.reason;
    const err = reason instanceof Error ? reason : new Error(String(reason));
    captureException(err, {
      tags: { component: 'unhandledrejection' },
      extra: { href: window.location.href, reason },
    });
  });
}
