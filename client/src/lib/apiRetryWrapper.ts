/**
 * API Retry Wrapper with Exponential Backoff
 * Handles quota limits, rate limiting, and network errors
 */

import axios, { AxiosError, AxiosRequestConfig, AxiosResponse } from 'axios';

interface RetryConfig {
  maxRetries: number;
  baseDelay: number;
  maxDelay: number;
  retryCondition?: (error: AxiosError) => boolean;
  onRetry?: (error: AxiosError, retryCount: number) => void;
}

export class APIRetryWrapper {
  private static instance: APIRetryWrapper;
  private retryConfig: RetryConfig;

  constructor() {
    this.retryConfig = {
      maxRetries: 5,
      baseDelay: 1000, // 1 second
      maxDelay: 60000, // 60 seconds
      retryCondition: this.shouldRetry.bind(this),
      onRetry: this.logRetry.bind(this)
    };
  }

  static getInstance(): APIRetryWrapper {
    if (!APIRetryWrapper.instance) {
      APIRetryWrapper.instance = new APIRetryWrapper();
    }
    return APIRetryWrapper.instance;
  }

  /**
   * Determine if error should trigger retry
   */
  private shouldRetry(error: AxiosError): boolean {
    if (!error.response) {
      // Network errors - always retry
      return true;
    }

    const status = error.response.status;
    const responseData = error.response.data as any;

    // Google API quota and rate limit errors
    if (status === 429) {
      console.log('🚫 Rate limit hit, will retry with exponential backoff');
      return true;
    }

    // Google API quota exceeded errors
    if (status === 403) {
      const errorReason = responseData?.error?.errors?.[0]?.reason;
      if (errorReason === 'quotaExceeded' || errorReason === 'rateLimitExceeded') {
        console.log('🚫 Google API quota exceeded, will retry');
        return true;
      }
    }

    // Server errors (5xx) - retry
    if (status >= 500) {
      console.log(`🚫 Server error ${status}, will retry`);
      return true;
    }

    // Session errors - single retry
    if (status === 401 && error.config && !(error.config as any)._hasRetried) {
      console.log('🚫 Session error, will retry once');
      return true;
    }

    // Timeout errors
    if (error.code === 'ECONNABORTED') {
      console.log('🚫 Request timeout, will retry');
      return true;
    }

    return false;
  }

  /**
   * Log retry attempts
   */
  private logRetry(error: AxiosError, retryCount: number): void {
    const status = error.response?.status || 'network';
    console.log(`🔄 API Retry ${retryCount}/${this.retryConfig.maxRetries} for ${status} error`);
  }

  /**
   * Calculate exponential backoff delay
   */
  private calculateDelay(retryCount: number, error?: AxiosError): number {
    let delay = this.retryConfig.baseDelay * Math.pow(2, retryCount - 1);
    
    // Add jitter to prevent thundering herd
    delay += Math.random() * 1000;
    
    // Check for Retry-After header (common in rate limiting)
    if (error?.response?.headers?.['retry-after']) {
      const retryAfter = parseInt(error.response.headers['retry-after']);
      if (!isNaN(retryAfter)) {
        delay = Math.max(delay, retryAfter * 1000);
      }
    }
    
    // Cap at maximum delay
    return Math.min(delay, this.retryConfig.maxDelay);
  }

  /**
   * Execute request with retry logic
   */
  async request<T = any>(config: AxiosRequestConfig): Promise<AxiosResponse<T>> {
    let lastError: AxiosError | undefined;
    
    for (let attempt = 1; attempt <= this.retryConfig.maxRetries + 1; attempt++) {
      try {
        // Add metadata to track retries (axios custom property)
        const requestConfig = {
          ...config,
          _retryAttempt: attempt,
          _hasRetried: attempt > 1
        };

        const response = await axios(requestConfig);
        
        // Success - log if this was a retry
        if (attempt > 1) {
          console.log(`✅ API request succeeded on attempt ${attempt}`);
        }
        
        return response;
        
      } catch (error) {
        lastError = error as AxiosError;
        
        // Don't retry on last attempt
        if (attempt > this.retryConfig.maxRetries) {
          break;
        }
        
        // Check if we should retry
        if (!this.retryConfig.retryCondition!(lastError)) {
          break;
        }
        
        // Log retry
        this.retryConfig.onRetry!(lastError, attempt);
        
        // Calculate and apply delay
        const delay = this.calculateDelay(attempt, lastError);
        console.log(`⏳ Waiting ${delay}ms before retry...`);
        await new Promise(resolve => setTimeout(resolve, delay));
      }
    }
    
    // All retries failed
    if (lastError) {
      console.error('❌ All API retries failed:', lastError.message);
      throw lastError;
    } else {
      throw new Error('API request failed with unknown error');
    }
  }

  /**
   * Convenience methods for common HTTP verbs
   */
  async get<T = any>(url: string, config?: AxiosRequestConfig): Promise<AxiosResponse<T>> {
    return this.request<T>({ ...config, method: 'GET', url });
  }

  async post<T = any>(url: string, data?: any, config?: AxiosRequestConfig): Promise<AxiosResponse<T>> {
    return this.request<T>({ ...config, method: 'POST', url, data });
  }

  async put<T = any>(url: string, data?: any, config?: AxiosRequestConfig): Promise<AxiosResponse<T>> {
    return this.request<T>({ ...config, method: 'PUT', url, data });
  }

  async delete<T = any>(url: string, config?: AxiosRequestConfig): Promise<AxiosResponse<T>> {
    return this.request<T>({ ...config, method: 'DELETE', url });
  }
}

// Create singleton instance
export const apiRetry = APIRetryWrapper.getInstance();

// Export as default for easy importing
export default apiRetry;