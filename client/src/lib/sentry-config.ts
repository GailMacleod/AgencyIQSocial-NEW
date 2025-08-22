// Sentry disabled shim - central caller for errors
declare global {
  interface Window { Sentry?: SentryShim; }
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

const devLog = (...args: unknown[]) => { if (import.meta.env.DEV) console.warn('[Sentry shim]', ...args); };  // Warn for console

const shim: SentryShim = {
  captureException(_error, _context) { devLog('captureException', _error, _context); },
  captureMessage(_message, _level) { devLog('captureMessage', _message, _level); },
  setUser(_user) { devLog('setUser', _user); },
  setTag(_key, _value) { devLog('setTag', _key, _value); },
  setContext(_key, _context) { devLog('setContext', _key, _context); },
  addBreadcrumb(_breadcrumb) { devLog('addBreadcrumb', _breadcrumb); },
  configureScope(_cb) { devLog('configureScope'); try { _cb({}); } catch {} },
};

export function initSentry() { window.Sentry = shim; }
initSentry();

export const captureException = (_error: unknown, _context?: CaptureContext) => window.Sentry?.captureException(_error, _context);
export const captureMessage = (_message: string, _level?: Level) => window.Sentry?.captureMessage(_message, _level);

export const sentryLogger = {
  error: captureException,
  info: (_message: string | unknown, _extra?: CaptureContext) => captureMessage(typeof _message === 'string' ? _message : String(_message), 'info'),
};

let handlersInstalled = false;
export function setupGlobalErrorHandlers() {
  if (handlersInstalled) return;
  handlersInstalled = true;
  window.addEventListener('error', (ev) => {
    const err = (ev as ErrorEvent).error ?? new Error((ev as ErrorEvent).message || 'Unknown');
    captureException(err, { tags: { component: 'window.error' }, extra: { href: window.location.href } });
  });
  window.addEventListener('unhandledrejection', (ev) => {
    const reason = (ev as PromiseRejectionEvent).reason;
    captureException(reason instanceof Error ? reason : new Error(String(reason) || 'Unhandled'), { tags: { component: 'unhandledrejection' }, extra: { href: window.location.href, reason } });
  });
}