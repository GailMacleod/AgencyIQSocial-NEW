// client/src/types/global.d.ts
// Global type augmentation for the Sentry shim.

type SentryLevel = 'fatal' | 'error' | 'warning' | 'log' | 'info' | 'debug';
type SentryContext = Record<string, unknown>;

    // Used elsewhere in your codebase:
    queryClient?: unknown;
  }

  interface Navigator {
    // iOS PWA detection used in PWASessionManager
    standalone?: boolean;
  }
}

export {};
