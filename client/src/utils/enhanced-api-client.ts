/**
 * Enhanced API Client with axios interceptor for backoff-retry on 429
 */
import axios, { AxiosInstance, AxiosError } from 'axios';

class EnhancedApiClient {
  private axiosInstance: AxiosInstance;
  private retryCount = 0;
  private maxRetries = 3;

  constructor() {
    this.axiosInstance = axios.create({
      baseURL: '',
      withCredentials: true,
      timeout: 30000,
      headers: {
        'Content-Type': 'application/json'
      }
    });

    // Add interceptor for backoff-retry on 429
    this.axiosInstance.interceptors.response.use(
      (response) => response,
      async (error: AxiosError) => {
        const { config, response } = error;
        
        if (response?.status === 429 && this.retryCount < this.maxRetries) {
          this.retryCount++;
          
          // Exponential backoff with jitter
          const baseDelay = Math.min(1000 * Math.pow(2, this.retryCount), 60000);
          const jitter = Math.random() * 0.1 * baseDelay;
          const delay = baseDelay + jitter;
          
          console.log(`🔄 Rate limited (429), retrying after ${delay}ms (attempt ${this.retryCount}/${this.maxRetries})`);
          
          await new Promise(resolve => setTimeout(resolve, delay));
          
          // Retry the request
          return this.axiosInstance.request(config!);
        }
        
        // Reset retry count on non-429 errors or max retries reached
        if (response?.status !== 429) {
          this.retryCount = 0;
        }
        
        return Promise.reject(error);
      }
    );
  }

  async get(url: string, config = {}) {
    return this.axiosInstance.get(url, config);
  }

  async post(url: string, data?: any, config = {}) {
    return this.axiosInstance.post(url, data, config);
  }

  async put(url: string, data?: any, config = {}) {
    return this.axiosInstance.put(url, data, config);
  }

  async delete(url: string, config = {}) {
    return this.axiosInstance.delete(url, config);
  }

  async patch(url: string, data?: any, config = {}) {
    return this.axiosInstance.patch(url, data, config);
  }
}

export const enhancedApiClient = new EnhancedApiClient();