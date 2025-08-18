/**
 * Enhanced Query Client with Quota Management
 * Integrates API retry wrapper with React Query
 */

import { QueryClient, QueryClientConfig } from '@tanstack/react-query';
import { apiRetry } from './apiRetryWrapper';
import { AxiosError } from 'axios';

interface EnhancedQueryConfig extends QueryClientConfig {
  enableQuotaManagement?: boolean;
  quotaRetryDelay?: number;
}

export class EnhancedQueryClient extends QueryClient {
  private quotaManagement: boolean;
  private quotaRetryDelay: number;

  constructor(config?: EnhancedQueryConfig) {
    const defaultConfig: QueryClientConfig = {
      defaultOptions: {
        queries: {
          retry: (failureCount, error) => {
            // Enhanced retry logic with quota awareness
            return this.shouldRetryQuery(failureCount, error);
          },
          retryDelay: (attemptIndex, error) => {
            // Use exponential backoff for retries
            return this.calculateQueryRetryDelay(attemptIndex, error);
          },
          staleTime: 5 * 60 * 1000, // 5 minutes
          gcTime: 10 * 60 * 1000, // 10 minutes (renamed from cacheTime)
          refetchOnWindowFocus: false,
          queryFn: async ({ queryKey, signal }) => {
            // Enhanced query function with retry wrapper
            return this.enhancedQueryFn(queryKey, signal);
          }
        },
        mutations: {
          retry: (failureCount, error) => {
            return this.shouldRetryMutation(failureCount, error);
          },
          retryDelay: (attemptIndex, error) => {
            return this.calculateMutationRetryDelay(attemptIndex, error);
          }
        }
      },
      ...config
    };

    super(defaultConfig);
    
    this.quotaManagement = config?.enableQuotaManagement ?? true;
    this.quotaRetryDelay = config?.quotaRetryDelay ?? 30000; // 30 seconds
  }

  /**
   * Enhanced query function with API retry wrapper
   */
  private async enhancedQueryFn(queryKey: readonly unknown[], signal?: AbortSignal): Promise<any> {
    const url = Array.isArray(queryKey) ? queryKey[0] : queryKey;
    
    if (typeof url !== 'string') {
      throw new Error('Query key must start with a string URL');
    }

    try {
      const response = await apiRetry.get(url, {
        signal,
        timeout: 30000, // 30 second timeout
        withCredentials: true,
        headers: {
          'Content-Type': 'application/json',
          'X-Quota-Management': this.quotaManagement ? 'enabled' : 'disabled'
        }
      });

      return response.data;
    } catch (error) {
      const axiosError = error as AxiosError;
      
      // Enhanced error handling for quota issues
      if (axiosError.response?.status === 429) {
        // Rate limited - throw with quota context
        throw new Error(`Rate limited: ${axiosError.message}`);
      }
      
      if (axiosError.response?.status === 403) {
        const responseData = axiosError.response.data as any;
        if (responseData?.error?.includes('quota')) {
          throw new Error(`Quota exceeded: ${responseData.error}`);
        }
      }
      
      throw error;
    }
  }

  /**
   * Enhanced query retry logic
   */
  private shouldRetryQuery(failureCount: number, error: any): boolean {
    // Max 3 retries for queries
    if (failureCount >= 3) {
      return false;
    }

    // Always retry network errors
    if (!error.response) {
      return true;
    }

    const status = error.response?.status;
    
    // Retry on rate limits and quota errors
    if (status === 429 || (status === 403 && error.message?.includes('quota'))) {
      return true;
    }
    
    // Retry on server errors
    if (status >= 500) {
      return true;
    }
    
    // Single retry for auth errors
    if (status === 401 && failureCount === 0) {
      return true;
    }
    
    return false;
  }

  /**
   * Enhanced mutation retry logic
   */
  private shouldRetryMutation(failureCount: number, error: any): boolean {
    // More conservative retry for mutations
    if (failureCount >= 2) {
      return false;
    }

    // Only retry network errors and 5xx for mutations
    if (!error.response || error.response.status >= 500) {
      return true;
    }
    
    // Retry rate limits for mutations
    if (error.response.status === 429) {
      return true;
    }
    
    return false;
  }

  /**
   * Calculate query retry delay
   */
  private calculateQueryRetryDelay(attemptIndex: number, error: any): number {
    // Check for quota-related errors
    if (error?.message?.includes('quota') || error?.message?.includes('Rate limited')) {
      return this.quotaRetryDelay;
    }
    
    // Exponential backoff: 1s, 2s, 4s
    return Math.min(1000 * Math.pow(2, attemptIndex), 30000);
  }

  /**
   * Calculate mutation retry delay
   */
  private calculateMutationRetryDelay(attemptIndex: number, error: any): number {
    // Longer delays for mutations
    if (error?.message?.includes('quota') || error?.message?.includes('Rate limited')) {
      return this.quotaRetryDelay * 2; // 60 seconds for mutation quota errors
    }
    
    // Exponential backoff: 2s, 4s, 8s
    return Math.min(2000 * Math.pow(2, attemptIndex), 60000);
  }

  /**
   * Enhanced invalidation with quota awareness
   */
  async invalidateQueriesWithQuotaCheck(filters?: any): Promise<void> {
    try {
      await this.invalidateQueries(filters);
    } catch (error) {
      console.warn('Query invalidation failed, possibly due to quota limits:', error);
      // Don't throw - invalidation failures shouldn't break the app
    }
  }

  /**
   * Batch query execution with quota management
   */
  async executeBatchQueries(queryKeys: string[], options?: any): Promise<any[]> {
    // Add delays between batch queries to respect rate limits
    const results = [];
    
    for (let i = 0; i < queryKeys.length; i++) {
      try {
        const result = await this.fetchQuery({
          queryKey: [queryKeys[i]],
          ...options
        });
        results.push(result);
        
        // Add delay between requests (except for last one)
        if (i < queryKeys.length - 1) {
          await new Promise(resolve => setTimeout(resolve, 100));
        }
      } catch (error) {
        console.warn(`Batch query failed for ${queryKeys[i]}:`, error);
        results.push(null);
      }
    }
    
    return results;
  }
}

// Create enhanced query client instance
export const enhancedQueryClient = new EnhancedQueryClient({
  enableQuotaManagement: true,
  quotaRetryDelay: 30000
});

export default enhancedQueryClient;