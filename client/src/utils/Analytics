// Define the gtag function globally
declare global {
  interface Window {
    dataLayer: any[];
    gtag: (...args: any[]) => void;
    Sentry?: {
      captureException: (error: Error) => void;
    };
  }
}

// Initialize Google Analytics with comprehensive error handling
export const initGA = () => {
  try {
    // Disable in development to avoid CORS issues
    if (process.env.NODE_ENV === 'development') {
      console.log('Analytics disabled in development mode');
      return;
    }

    const measurementId = import.meta.env.VITE_GA_MEASUREMENT_ID;

    if (!measurementId) {
      console.warn('Missing required Google Analytics key: VITE_GA_MEASUREMENT_ID');
      // Report missing key to Sentry if available
      if (window.Sentry) {
        window.Sentry.captureException(new Error('GA initialization failed: Missing VITE_GA_MEASUREMENT_ID'));
      }
      return;
    }

    // Validate measurement ID format
    if (!/^G-[A-Z0-9]+$/.test(measurementId)) {
      const error = new Error(`Invalid GA measurement ID format: ${measurementId}`);
      console.error('GA initialization failed:', error.message);
      if (window.Sentry) {
        window.Sentry.captureException(error);
      }
      return;
    }

    // Add Google Analytics script to the head with error handling
    const script1 = document.createElement('script');
    script1.async = true;
    script1.src = `https://www.googletagmanager.com/gtag/js?id=${measurementId}`;
    script1.onerror = (error) => {
      console.error('Failed to load GA script:', error);
      if (window.Sentry) {
        window.Sentry.captureException(new Error('GA script loading failed'));
      }
    };
    document.head.appendChild(script1);

    // Initialize gtag with error handling
    const script2 = document.createElement('script');
    script2.innerHTML = `
      try {
        window.dataLayer = window.dataLayer || [];
        function gtag(){
          try {
            dataLayer.push(arguments);
          } catch (e) {
            console.error('gtag push error:', e);
            if (window.Sentry) window.Sentry.captureException(e);
          }
        }
        gtag('js', new Date());
        gtag('config', '${measurementId}');
        console.log('Google Analytics initialized successfully');
      } catch (e) {
        console.error('GA initialization script error:', e);
        if (window.Sentry) window.Sentry.captureException(e);
      }
    `;
    script2.onerror = (error) => {
      console.error('GA initialization script failed:', error);
      if (window.Sentry) {
        window.Sentry.captureException(new Error('GA initialization script execution failed'));
      }
    };
    document.head.appendChild(script2);

  } catch (error) {
    const errorObj = error instanceof Error ? error : new Error(String(error));
    console.error('GA initialization failed:', errorObj);
    if (window.Sentry) {
      window.Sentry.captureException(errorObj);
    }
  }
};

// Track page views - useful for single-page applications
export const trackPageView = (url: string) => {
  if (typeof window === 'undefined' || !window.gtag) return;
  
  const measurementId = import.meta.env.VITE_GA_MEASUREMENT_ID;
  if (!measurementId) return;
  
  window.gtag('config', measurementId, {
    page_path: url
  });
};

// Track events
export const trackEvent = (
  action: string, 
  category?: string, 
  label?: string, 
  value?: number
) => {
  if (typeof window === 'undefined' || !window.gtag) return;
  
  window.gtag('event', action, {
    event_category: category,
    event_label: label,
    value: value,
  });
};

// Track social media post engagement
export const trackSocialEngagement = (platform: string, action: string, content: string) => {
  trackEvent('social_engagement', platform, action, 1);
  trackEvent(`${platform}_${action}`, 'social_media', content);
};

// Track content generation
export const trackContentGeneration = (platform: string, contentType: string) => {
  trackEvent('content_generated', 'ai_content', `${platform}_${contentType}`, 1);
};

// Track user journey milestones
export const trackMilestone = (milestone: string) => {
  trackEvent('milestone_reached', 'user_journey', milestone, 1);
};