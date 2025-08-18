// Facebook SDK integration utility for TheAgencyIQ
// Provides enhanced social media platform integration alongside Meta Pixel

declare global {
  interface Window {
    FB: any;
    fbAsyncInit: () => void;
  }
}

export class FacebookSDK {
  private static isInitialized = false;
  private static initializationPromise: Promise<void> | null = null;

  /**
   * Ensure Facebook SDK is loaded and initialized
   */
  static async initialize(): Promise<void> {
    if (this.isInitialized) {
      return;
    }

    if (this.initializationPromise) {
      return this.initializationPromise;
    }

    this.initializationPromise = new Promise((resolve) => {
      // Check if FB is already available
      if (typeof window !== 'undefined' && window.FB) {
        this.isInitialized = true;
        resolve();
        return;
      }

      // Wait for FB to be initialized
      const checkFB = () => {
        if (typeof window !== 'undefined' && window.FB) {
          this.isInitialized = true;
          resolve();
        } else {
          setTimeout(checkFB, 100);
        }
      };

      checkFB();
    });

    return this.initializationPromise;
  }

  /**
   * Log a page view event
   */
  static async logPageView(pageName?: string): Promise<void> {
    await this.initialize();
    
    try {
      if (window.FB && window.FB.AppEvents) {
        window.FB.AppEvents.logPageView();
        
        if (pageName) {
          window.FB.AppEvents.logEvent('PageView', null, { page_name: pageName });
        }
        
        console.log('Facebook SDK: Page view logged', pageName || 'default');
      }
    } catch (error) {
      console.error('Facebook SDK: Error logging page view:', error);
    }
  }

  /**
   * Log a custom event
   */
  static async logEvent(eventName: string, parameters?: any): Promise<void> {
    await this.initialize();
    
    try {
      if (window.FB && window.FB.AppEvents) {
        window.FB.AppEvents.logEvent(eventName, null, parameters);
        console.log('Facebook SDK: Custom event logged:', eventName, parameters);
      }
    } catch (error) {
      console.error('Facebook SDK: Error logging event:', error);
    }
  }

  /**
   * Log a purchase event
   */
  static async logPurchase(value: number, currency = 'AUD', parameters?: any): Promise<void> {
    await this.initialize();
    
    try {
      if (window.FB && window.FB.AppEvents) {
        window.FB.AppEvents.logPurchase(value, currency, parameters);
        console.log('Facebook SDK: Purchase logged:', value, currency, parameters);
      }
    } catch (error) {
      console.error('Facebook SDK: Error logging purchase:', error);
    }
  }

  /**
   * Log a lead generation event
   */
  static async logLead(parameters?: any): Promise<void> {
    await this.initialize();
    
    try {
      if (window.FB && window.FB.AppEvents) {
        window.FB.AppEvents.logEvent('Lead', null, parameters);
        console.log('Facebook SDK: Lead logged:', parameters);
      }
    } catch (error) {
      console.error('Facebook SDK: Error logging lead:', error);
    }
  }

  /**
   * Log a registration event
   */
  static async logRegistration(method: string, parameters?: any): Promise<void> {
    await this.initialize();
    
    try {
      if (window.FB && window.FB.AppEvents) {
        window.FB.AppEvents.logEvent('CompleteRegistration', null, {
          registration_method: method,
          ...parameters
        });
        console.log('Facebook SDK: Registration logged:', method, parameters);
      }
    } catch (error) {
      console.error('Facebook SDK: Error logging registration:', error);
    }
  }

  /**
   * Log content view
   */
  static async logContentView(contentType: string, contentId: string, parameters?: any): Promise<void> {
    await this.initialize();
    
    try {
      if (window.FB && window.FB.AppEvents) {
        window.FB.AppEvents.logEvent('ViewContent', null, {
          content_type: contentType,
          content_id: contentId,
          ...parameters
        });
        console.log('Facebook SDK: Content view logged:', contentType, contentId, parameters);
      }
    } catch (error) {
      console.error('Facebook SDK: Error logging content view:', error);
    }
  }

  /**
   * Log search event
   */
  static async logSearch(searchString: string, parameters?: any): Promise<void> {
    await this.initialize();
    
    try {
      if (window.FB && window.FB.AppEvents) {
        window.FB.AppEvents.logEvent('Search', null, {
          search_string: searchString,
          ...parameters
        });
        console.log('Facebook SDK: Search logged:', searchString, parameters);
      }
    } catch (error) {
      console.error('Facebook SDK: Error logging search:', error);
    }
  }

  /**
   * Check if SDK is available and initialized
   */
  static isAvailable(): boolean {
    return typeof window !== 'undefined' && 
           window.FB && 
           window.FB.AppEvents && 
           this.isInitialized;
  }

  /**
   * Get SDK status for debugging
   */
  static getStatus(): {
    isInitialized: boolean;
    isAvailable: boolean;
    fbExists: boolean;
    appEventsExists: boolean;
  } {
    return {
      isInitialized: this.isInitialized,
      isAvailable: this.isAvailable(),
      fbExists: typeof window !== 'undefined' && !!window.FB,
      appEventsExists: typeof window !== 'undefined' && !!window.FB?.AppEvents
    };
  }
}

// TheAgencyIQ specific tracking methods
export class AgencyIQFacebookTracking {
  /**
   * Track subscription purchase
   */
  static async trackSubscriptionPurchase(plan: string, value: number): Promise<void> {
    await Promise.all([
      FacebookSDK.logPurchase(value, 'AUD', {
        content_type: 'subscription',
        subscription_plan: plan,
        business_type: 'social_media_automation',
        product_category: 'saas'
      }),
      FacebookSDK.logEvent('Subscribe', {
        subscription_plan: plan,
        value: value,
        currency: 'AUD'
      })
    ]);
  }

  /**
   * Track gift certificate redemption
   */
  static async trackGiftCertificateRedemption(certificateId: string, value: number): Promise<void> {
    await Promise.all([
      FacebookSDK.logEvent('RedeemGiftCertificate', {
        certificate_id: certificateId,
        value: value,
        currency: 'AUD'
      }),
      FacebookSDK.logLead({
        lead_type: 'gift_certificate_redemption',
        value: value
      })
    ]);
  }

  /**
   * Track user registration
   */
  static async trackUserRegistration(method: string, subscriptionPlan?: string): Promise<void> {
    await FacebookSDK.logRegistration(method, {
      subscription_plan: subscriptionPlan,
      business_type: 'social_media_automation',
      user_type: 'business_owner'
    });
  }

  /**
   * Track post generation
   */
  static async trackPostGeneration(platform: string, postCount: number): Promise<void> {
    await FacebookSDK.logEvent('GenerateContent', {
      content_type: 'social_media_post',
      platform: platform,
      post_count: postCount,
      feature_used: 'ai_content_generation'
    });
  }

  /**
   * Track platform connection
   */
  static async trackPlatformConnection(platform: string): Promise<void> {
    await FacebookSDK.logEvent('ConnectPlatform', {
      platform: platform,
      feature_used: 'oauth_integration'
    });
  }

  /**
   * Track analytics view
   */
  static async trackAnalyticsView(analyticsType: string): Promise<void> {
    await FacebookSDK.logContentView('analytics', analyticsType, {
      feature_used: 'performance_analytics'
    });
  }
}