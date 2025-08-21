- import * as Sentry from '@sentry/node'; // Remove this line entirely
+ import './utils/sentry-config.ts'; // Import shim (adjust path if utils folder doesn't exist; create it)

- Sentry.init({
-   dsn: process.env.SENTRY_DSN, // Or whatever init was here
-   // ... other config like integrations, tracesSampleRate
- }); // Remove entire init block

// Keep any other code, but replace calls like:
- Sentry.captureException(error, { tags: { service: 'oauth' } });
+ captureException(error, { tags: { service: 'oauth' } }); // Or global.Sentry if preferred

export function initializeClientMonitoring() {
  if (import.meta.env.PROD) {
    Sentry.init({
      dsn: import.meta.env.VITE_SENTRY_DSN,
      environment: import.meta.env.MODE,
      integrations: [
        Sentry.browserTracingIntegration(),
        Sentry.replayIntegration(),
      ],
      tracesSampleRate: 1.0,
      replaysSessionSampleRate: 0.1,- import * as Sentry from '@sentry/node'; // Remove this line entirely
+ import './utils/sentry-config.ts'; // Import shim (adjust path if utils folder doesn't exist; create it)

- Sentry.init({
-   dsn: process.env.SENTRY_DSN, // Or whatever init was here
-   // ... other config like integrations, tracesSampleRate
- }); // Remove entire init block

// Keep any other code, but replace calls like:
- Sentry.captureException(error, { tags: { service: 'oauth' } });
+ captureException(error, { tags: { service: 'oauth' } }); // Or global.Sentry if preferred

export function initializeClientMonitoring() {
  if (import.meta.env.PROD) {
    Sentry.init({
      dsn: import.meta.env.VITE_SENTRY_DSN,
      environment: import.meta.env.MODE,
      integrations: [
        Sentry.browserTracingIntegration(),
        Sentry.replayIntegration(),
      ],
      tracesSampleRate: 1.0,
      replaysSessionSampleRate: 0.1,
      replaysOnErrorSampleRate: 1.0,
    });
  }
}

export function logClientError(error: Error, context?: any) {
  if (import.meta.env.PROD) {
    Sentry.captureException(error, { extra: context });
  } else {
    console.error('Client Error:', error.message, context);
  }
}

export function setUserContext(user: any) {
  if (import.meta.env.PROD) {
    Sentry.setUser({
      id: user.id,
      email: user.email,
    });
  }
}
      replaysOnErrorSampleRate: 1.0,
    });
  }
}

export function logClientError(error: Error, context?: any) {
  if (import.meta.env.PROD) {
    Sentry.captureException(error, { extra: context });
  } else {
    console.error('Client Error:', error.message, context);
  }
}

export function setUserContext(user: any) {
  if (import.meta.env.PROD) {
    Sentry.setUser({
      id: user.id,
      email: user.email,
    });
  }
}