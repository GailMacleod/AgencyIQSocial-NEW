// Development environment configuration
export const isDevelopment = (): boolean => {
  return process.env.NODE_ENV === 'development' || import.meta.env.DEV;
};

// Disable third-party services in development
export const shouldDisableThirdParty = (): boolean => {
  return isDevelopment();
};

// Service configuration based on environment
export const getServiceConfig = () => {
  const isDev = isDevelopment();
  
  return {
    analytics: {
      enabled: !isDev,
      measurementId: import.meta.env.VITE_GA_MEASUREMENT_ID,
    },
    launchDarkly: {
      enabled: false, // Disabled completely due to CORS issues
      clientSideId: import.meta.env.VITE_LAUNCH_DARKLY_CLIENT_ID,
    },
    metaPixel: {
      enabled: true, // Keep enabled for testing
      pixelId: import.meta.env.VITE_META_PIXEL_ID,
    },
    seedance: {
      enabled: true,
      apiKey: import.meta.env.VITE_SEEDANCE_API_KEY,
    },
  };
};