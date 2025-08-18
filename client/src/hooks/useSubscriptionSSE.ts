import { useEffect, useRef, useState } from 'react';
import { useQueryClient } from '@tanstack/react-query';
import { useToast } from '@/hooks/use-toast';

interface SubscriptionStatus {
  plan: string;
  active: boolean;
  remainingPosts: number;
  totalPosts: number;
  usage: number;
}

interface SSEMessage {
  type: string;
  data: any;
  timestamp: string;
}

export function useSubscriptionSSE() {
  const [status, setStatus] = useState<SubscriptionStatus | null>(null);
  const [isConnected, setIsConnected] = useState(false);
  const eventSourceRef = useRef<EventSource | null>(null);
  const queryClient = useQueryClient();
  const { toast } = useToast();
  const reconnectTimeoutRef = useRef<NodeJS.Timeout | null>(null);
  const reconnectAttempts = useRef(0);
  const maxReconnectAttempts = 5;

  const connect = () => {
    if (eventSourceRef.current) {
      eventSourceRef.current.close();
    }

    console.log('🔗 [SSE] Connecting to subscription status updates...');
    const eventSource = new EventSource('/api/subscription-status-sse');
    eventSourceRef.current = eventSource;

    eventSource.onopen = () => {
      console.log('✅ [SSE] Connected to subscription updates');
      setIsConnected(true);
      reconnectAttempts.current = 0;
    };

    eventSource.onmessage = (event) => {
      try {
        const message: SSEMessage = JSON.parse(event.data);
        console.log('📡 [SSE] Received message:', message.type);

        switch (message.type) {
          case 'connected':
            console.log('🎉 [SSE] Connection confirmed');
            break;

          case 'subscription_status':
            setStatus(message.data);
            // Invalidate relevant queries to trigger UI updates
            queryClient.invalidateQueries({ queryKey: ['/api/user-status'] });
            queryClient.invalidateQueries({ queryKey: ['/api/quota-status'] });
            console.log('📊 [SSE] Subscription status updated:', message.data);
            break;

          case 'subscription_cancelled':
            setStatus(message.data);
            
            // Show user notification
            toast({
              title: "Subscription Cancelled",
              description: "Your subscription has been cancelled. You will be redirected to login.",
              variant: "destructive",
            });

            // Clear session and redirect if instructed
            if (message.data.action === 'clearSession') {
              // Clear local storage and session storage
              localStorage.clear();
              sessionStorage.clear();
              
              // Clear cookies
              document.cookie = 'theagencyiq.session=; expires=Thu, 01 Jan 1970 00:00:00 GMT; path=/';
              document.cookie = 'aiq_backup_session=; expires=Thu, 01 Jan 1970 00:00:00 GMT; path=/';
              
              // Invalidate all queries
              queryClient.clear();
              
              // Redirect after short delay
              setTimeout(() => {
                window.location.href = message.data.redirectTo || '/api/login';
              }, 2000);
            }
            break;

          case 'ping':
            // Keep-alive ping, no action needed
            break;

          default:
            console.log('🔔 [SSE] Unknown message type:', message.type);
        }
      } catch (error) {
        console.error('❌ [SSE] Error parsing message:', error);
      }
    };

    eventSource.onerror = (error) => {
      console.error('❌ [SSE] Connection error:', error);
      setIsConnected(false);
      
      // Attempt reconnection with exponential backoff
      if (reconnectAttempts.current < maxReconnectAttempts) {
        const delay = Math.min(1000 * Math.pow(2, reconnectAttempts.current), 30000);
        console.log(`🔄 [SSE] Reconnecting in ${delay}ms (attempt ${reconnectAttempts.current + 1})`);
        
        reconnectTimeoutRef.current = setTimeout(() => {
          reconnectAttempts.current++;
          connect();
        }, delay);
      } else {
        console.error('🚫 [SSE] Max reconnection attempts reached');
        toast({
          title: "Connection Lost",
          description: "Real-time updates are temporarily unavailable. Please refresh the page.",
          variant: "destructive",
        });
      }
    };
  };

  const disconnect = () => {
    if (eventSourceRef.current) {
      eventSourceRef.current.close();
      eventSourceRef.current = null;
    }
    
    if (reconnectTimeoutRef.current) {
      clearTimeout(reconnectTimeoutRef.current);
      reconnectTimeoutRef.current = null;
    }
    
    setIsConnected(false);
    console.log('🔌 [SSE] Disconnected from subscription updates');
  };

  useEffect(() => {
    connect();

    // Cleanup on unmount
    return () => {
      disconnect();
    };
  }, []);

  // Handle page visibility changes
  useEffect(() => {
    const handleVisibilityChange = () => {
      if (document.hidden) {
        // Page is hidden, maintain connection but reduce activity
        console.log('👁️ [SSE] Page hidden, maintaining connection');
      } else {
        // Page is visible, ensure connection is active
        console.log('👁️ [SSE] Page visible, checking connection');
        if (!isConnected && reconnectAttempts.current < maxReconnectAttempts) {
          connect();
        }
      }
    };

    document.addEventListener('visibilitychange', handleVisibilityChange);
    return () => document.removeEventListener('visibilitychange', handleVisibilityChange);
  }, [isConnected]);

  return {
    status,
    isConnected,
    reconnect: connect,
    disconnect
  };
}