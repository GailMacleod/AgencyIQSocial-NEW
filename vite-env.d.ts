/// <reference types="vite/client" />
interface ImportMetaEnv {
  readonly VITE_GA_MEASUREMENT_ID: string;
  readonly VITE_SENTRY_DSN: string;
  readonly VITE_LAUNCH_DARKLY_CLIENT_ID: string;
  readonly VITE_META_PIXEL_ID: string;
  readonly VITE_STRIPE_PRICE_ID_STARTER: string;
  readonly VITE_STRIPE_PRICE_ID_GROWTH: string;
  readonly VITE_STRIPE_PRICE_ID_PROFESSIONAL: string;
  readonly MODE: string;
  readonly DEV: boolean;
  readonly PROD: boolean;
}