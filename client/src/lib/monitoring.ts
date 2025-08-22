// client/src/lib/monitoring.ts
// Monitoring/Sentry disabled build-safe helpers.
// We load the no-cost shim so window.Sentry exists if other code calls it.
import '@/lib/sentry-config';

type Ctx = Record<string, unknown>;
type Level = 'fatal' | 'error' | 'warning' | 'log' | 'info' | 'debug';

function sentry() {
  return (window as unknown as {
    Sentry?: {
      captureException: (error: Error, context?: Ctx) => void;
      captureMessage?: (message: string, level?: string) => void;
      setUser?: (user: Record<string, unknown> | null) => void;
      setTag?: (key: string, value: string) => void;
      setContext?: (key: string, context: Ctx | null) => void;
    };
  }).Sentry;
}

export function initMonitoring(): void {
  // No-op; shim is already attached by importing sentry-config above.
}

export function captureException(error: unknown, context?: Ctx): void {
  sentry()?.captureException(error as Error, context);
}

export function captureMessage(message: string, level?: Level): void {
  sentry()?.captureMessage?.(message, level);
}

export function setUser(user: Record<string, unknown> | null): void {
  sentry()?.setUser?.(user);
}

export function setTag(key: string, value: string): void {
  sentry()?.setTag?.(key, value);
}

export function setContext(key: string, context: Ctx | null): void {
  sentry()?.setContext?.(key, context);
}

// Optional default export for convenience in places that do `import monitoring from ...`
const Monitoring = {
  init: initMonitoring,
  captureException,
  captureMessage,
  setUser,
  setTag,
  setContext,
};

export default Monitoring;
