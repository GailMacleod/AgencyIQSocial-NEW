// Microservice URLs configuration
const MICROSERVICE_ENDPOINTS = {
  phoneUpdate: process.env.NODE_ENV === 'production' 
    ? 'https://your-ngrok-url.ngrok.io' 
    : 'http://localhost:3000'
};

export async function apiRequest(
  method: string,
  url: string,
  data?: unknown,
): Promise<any> {
  console.log(`API call to ${url} starting with method ${method}`);
  
  try {
    // Reduced timeout for API requests (10 seconds)
    const controller = new AbortController();
    const timeoutId = setTimeout(() => {
      console.warn('API request timeout for:', method, url);
      controller.abort('API request timeout after 10 seconds');
    }, 10000);

    // Use main app endpoints, not microservice
    const response = await fetch(url, {
      method,
      headers: { 
        "Content-Type": "application/json",
        "Accept": "application/json"
      },
      body: data ? JSON.stringify(data) : undefined,
      credentials: "include",
      signal: controller.signal
    });

    clearTimeout(timeoutId);
    console.log(`API call to ${url} returned ${response.status}`);
    
    // Parse response as JSON
    const result = await response.json();
    
    if (!response.ok) {
      console.error(`API error:`, result);
      throw new Error(result.error || result.message || 'Server error');
    }
    
    return result;
    
  } catch (error: any) {
    // Enhanced error handling for AbortController issues
    if (error.name === 'AbortError') {
      const reason = error.message || 'Request was aborted';
      console.error('AbortError in apiRequest:', reason, 'for', method, url);
      throw new Error(`API request timeout: ${reason}`);
    } else if (error.message?.includes('signal is aborted without reason')) {
      console.error('AbortController signal issue in apiRequest:', error.message, 'for', method, url);
      throw new Error('API request was cancelled due to timeout');
    } else if (error.message?.includes('Failed to fetch') || error.message?.includes('NetworkError')) {
      console.error('Network error in apiRequest:', error.message, 'for', method, url);
      throw new Error('Network connection failed');
    }
    
    // Log unexpected errors for debugging
    console.error('Unexpected API request error:', error, 'for', method, url);
    throw error;
  }
}

// Microservice-specific API function
export async function microserviceRequest(
  method: string,
  endpoint: string,
  data?: unknown,
): Promise<Response> {
  console.log(`Microservice call to ${endpoint} with method ${method}`);
  
  const response = await fetch(`${MICROSERVICE_ENDPOINTS.phoneUpdate}${endpoint}`, {
    method,
    headers: data ? { "Content-Type": "application/json" } : {},
    body: data ? JSON.stringify(data) : undefined,
  });

  console.log(`Microservice call to ${endpoint} returned ${response.status}`);

  if (!response.ok) {
    const text = await response.text();
    console.error('Microservice error:', text);
    
    try {
      const errorData = JSON.parse(text);
      throw new Error(errorData.error || errorData.message || 'Microservice error');
    } catch (parseError) {
      throw new Error('Microservice error: ' + text.substring(0, 50));
    }
  }

  return response;
}
