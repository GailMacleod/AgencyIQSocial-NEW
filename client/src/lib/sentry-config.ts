// Minimal, safe Sentry bootstrap for Vite/React apps.
// - Uses import.meta.env (Vite) instead of process.env
// - Lazy-loads @sentry/react only in production when a DSN exists
// - Exposes window.Sentry.captureException for legacy call sites

type CaptureContext = Record<string, unknown>;

type SentryWindow = Window & {
  Sentry?: {
    captureException: (error: Error, context?: CaptureContext) => void;
  };
};

type SentryModule = {
  init: (options: { dsn: string; environment?: string }) => void;
  captureException: (error: unknown, context?: unknown) => void;
};

export async function initSentry(): Promise<void> {
  const isProd = import.meta.env.PROD;
  const dsn = import.meta.env.VITE_SENTRY_DSN;

  const w = window as SentryWindow;

  if (!isProd || !dsn) {
    // No-op shim so window.Sentry calls don't crash in dev or when DSN is missing
    w.Sentry = { captureException: () => void 0 };
    return;
  }

  try {
    // Dynamic import with a variable module ID so TS doesn't require type declarations at build time.
    // @vite-ignore prevents Vite from trying to pre-bundle it when not installed.
    const moduleId = '@sentry/react' as string;
    const Sentry = (await import(/* @vite-ignore */ moduleId)) as unknown as SentryModule;

    Sentry.init({
      dsn,
      environment: import.meta.env.MODE,
    });

    // Expose a tiny shim for existing window.Sentry usages
    w.Sentry = {
      captureException: (error: Error, context?: CaptureContext) => {
        Sentry.captureException(error, context);
      },
    };
  } catch {
    // If the SDK isn't installed or failed to load, keep a no-op shim.
    w.Sentry = { captureException: () => void 0 };
  }
}

// If you import this module for side-effects, auto-initialize safely.
// Comment this out if you prefer to call initSentry() manually from main.tsx.
void initSentry();
