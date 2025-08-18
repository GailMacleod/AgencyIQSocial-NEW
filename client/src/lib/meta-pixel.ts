// Meta Pixel Analytics Utility for TheAgencyIQ
// Tracks user interactions and conversions for Facebook/Instagram campaigns

declare global {
  interface Window {
    fbq: any;
  }
}

export interface MetaPixelEvent {
  eventName: string;
  parameters?: Record<string, any>;
  customData?: Record<string, any>;
}

export class MetaPixelTracker {
  private static pixelId = '1409057863445071';
  private static isInitialized = false;

  static initialize(): void {
    if (this.isInitialized || typeof window === 'undefined') return;
    
    try {
      // Verify Meta Pixel is loaded
      if (window.fbq) {
        this.isInitialized = true;
        console.log('Meta Pixel initialized successfully');
      } else {
        console.warn('Meta Pixel not loaded - check pixel code installation');
      }
    } catch (error) {
      console.error('Meta Pixel initialization error:', error);
    }
  }

  // Core tracking methods
  static trackEvent(eventName: string, parameters?: Record<string, any>): void {
    if (!this.isInitialized || !window.fbq) return;

    try {
      if (parameters) {
        window.fbq('track', eventName, parameters);
      } else {
        window.fbq('track', eventName);
      }
      console.log(`Meta Pixel tracked: ${eventName}`, parameters);
    } catch (error) {
      console.error('Meta Pixel tracking error:', error);
    }
  }

  static trackCustomEvent(eventName: string, customData?: Record<string, any>): void {
    if (!this.isInitialized || !window.fbq) return;

    try {
      window.fbq('trackCustom', eventName, customData || {});
      console.log(`Meta Pixel custom event: ${eventName}`, customData);
    } catch (error) {
      console.error('Meta Pixel custom tracking error:', error);
    }
  }

  // Business-specific tracking methods for TheAgencyIQ
  static trackSubscriptionPurchase(plan: string, value: number, currency = 'AUD'): void {
    this.trackEvent('Purchase', {
      value: value,
      currency: currency,
      content_name: `${plan} Subscription`,
      content_category: 'subscription',
      content_type: 'product'
    });
  }

  static trackGiftCertificateRedeem(code: string, plan: string): void {
    this.trackCustomEvent('GiftCertificateRedeemed', {
      certificate_code: code,
      subscription_plan: plan,
      value_type: 'free_trial'
    });
  }

  static trackPlatformConnection(platform: string, success: boolean): void {
    this.trackCustomEvent('PlatformConnected', {
      platform: platform,
      connection_success: success,
      step: 'oauth_completion'
    });
  }

  static trackPostGeneration(platform: string, postCount: number, isAI: boolean = true): void {
    this.trackCustomEvent('ContentGenerated', {
      platform: platform,
      post_count: postCount,
      generation_type: isAI ? 'ai_generated' : 'manual',
      content_category: 'social_media_post'
    });
  }

  static trackPostApproval(platform: string, approved: boolean): void {
    this.trackCustomEvent('PostApproved', {
      platform: platform,
      approval_status: approved ? 'approved' : 'rejected',
      action_type: 'content_review'
    });
  }

  static trackPostPublish(platform: string, scheduledFor?: Date): void {
    this.trackEvent('Schedule', {
      content_type: 'social_media_post',
      platform: platform,
      scheduled: !!scheduledFor,
      publish_time: scheduledFor?.toISOString() || 'immediate'
    });
  }

  static trackBrandPurposeCompletion(hasLogo: boolean, platforms: string[]): void {
    this.trackEvent('CompleteRegistration', {
      registration_method: 'brand_purpose_form',
      has_logo: hasLogo,
      platform_count: platforms.length,
      platforms: platforms.join(',')
    });
  }

  static trackAnalyticsView(timeframe: string, platforms: string[]): void {
    this.trackCustomEvent('AnalyticsViewed', {
      timeframe: timeframe,
      platforms: platforms.join(','),
      view_type: 'performance_dashboard'
    });
  }

  static trackUserRegistration(method: string, subscriptionTier: string): void {
    this.trackEvent('CompleteRegistration', {
      registration_method: method,
      subscription_tier: subscriptionTier,
      value: this.getSubscriptionValue(subscriptionTier),
      currency: 'AUD'
    });
  }

  static trackPageView(pageName: string, category?: string): void {
    this.trackEvent('PageView', {
      page_name: pageName,
      page_category: category || 'general',
      timestamp: new Date().toISOString()
    });
  }

  static trackSearch(searchTerm: string, category: string): void {
    this.trackEvent('Search', {
      search_string: searchTerm,
      content_category: category
    });
  }

  static trackLead(leadType: string, value?: number): void {
    this.trackEvent('Lead', {
      lead_type: leadType,
      value: value || 0,
      currency: 'AUD'
    });
  }

  // Utility methods
  private static getSubscriptionValue(tier: string): number {
    const values = {
      'Starter': 47,
      'Growth': 97,
      'Professional': 197
    };
    return values[tier as keyof typeof values] || 0;
  }

  // Advanced tracking for conversion optimisation
  static trackConversionFunnel(step: string, data?: Record<string, any>): void {
    this.trackCustomEvent('FunnelStep', {
      funnel_step: step,
      timestamp: new Date().toISOString(),
      ...data
    });
  }

  static trackFeatureUsage(feature: string, usage_data?: Record<string, any>): void {
    this.trackCustomEvent('FeatureUsed', {
      feature_name: feature,
      usage_timestamp: new Date().toISOString(),
      ...usage_data
    });
  }

  // Error and performance tracking
  static trackError(errorType: string, errorMessage: string, context?: Record<string, any>): void {
    this.trackCustomEvent('ApplicationError', {
      error_type: errorType,
      error_message: errorMessage,
      error_context: JSON.stringify(context || {}),
      timestamp: new Date().toISOString()
    });
  }

  static trackPerformance(action: string, duration: number, success: boolean): void {
    this.trackCustomEvent('PerformanceMetric', {
      action: action,
      duration_ms: duration,
      success: success,
      timestamp: new Date().toISOString()
    });
  }
}

// Auto-initialize when module loads
if (typeof window !== 'undefined') {
  // Wait for pixel to load before initializing
  setTimeout(() => {
    MetaPixelTracker.initialize();
  }, 1000);
}