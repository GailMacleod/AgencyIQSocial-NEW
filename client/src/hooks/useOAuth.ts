/**
 * OAuth Hook with automatic token refresh and error handling
 */

import { useState, useEffect } from 'react';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { oauthManager, getValidToken, handleTokenFailure } from '@/lib/oauthManager';
import { useToast } from '@/hooks/use-toast';

interface UseOAuthResult {
  tokens: Record<string, any>;
  status: Record<string, any>;
  isLoading: boolean;
  refreshToken: (provider: string) => Promise<boolean>;
  revokeToken: (provider: string) => Promise<boolean>;
  logout: (provider?: string) => Promise<boolean>;
  hasValidToken: (provider: string) => boolean;
  getToken: (provider: string) => Promise<string | null>;
}

export function useOAuth(): UseOAuthResult {
  const { toast } = useToast();
  const queryClient = useQueryClient();
  const [isInitialized, setIsInitialized] = useState(false);

  // Initialize OAuth manager
  useEffect(() => {
    const initializeOAuth = async () => {
      try {
        await oauthManager.initializeTokens();
        setIsInitialized(true);
        console.log('✅ OAuth manager initialized');
      } catch (error) {
        console.error('❌ OAuth initialization failed:', error);
        setIsInitialized(true); // Continue even if initialization fails
      }
    };

    initializeOAuth();
  }, []);

  // Get OAuth tokens
  const { data: tokens = {}, isLoading: tokensLoading } = useQuery({
    queryKey: ['/api/oauth/tokens'],
    enabled: isInitialized,
    retry: 1,
    staleTime: 5 * 60 * 1000, // 5 minutes
  });

  // Get OAuth status
  const { data: statusData, isLoading: statusLoading } = useQuery({
    queryKey: ['/api/oauth/status'],
    enabled: isInitialized,
    retry: 1,
    staleTime: 2 * 60 * 1000, // 2 minutes
  });
  
  const status = (statusData as Record<string, any>) || {};

  // Token refresh mutation
  const refreshMutation = useMutation({
    mutationFn: async (provider: string) => {
      const response = await fetch('/api/oauth/refresh', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ provider }),
      });

      if (!response.ok) {
        throw new Error(`Token refresh failed for ${provider}`);
      }

      return response.json();
    },
    onSuccess: (data, provider) => {
      // Invalidate token queries to refetch
      queryClient.invalidateQueries({ queryKey: ['/api/oauth/tokens'] });
      queryClient.invalidateQueries({ queryKey: ['/api/oauth/status'] });
      
      toast({
        title: "Token Refreshed",
        description: `${provider} connection refreshed successfully`,
      });
    },
    onError: (error: any, provider) => {
      console.error(`Token refresh failed for ${provider}:`, error);
      
      toast({
        title: "Token Refresh Failed",
        description: `Failed to refresh ${provider} connection. Please reconnect manually.`,
        variant: "destructive",
      });
    },
  });

  // Token revocation mutation
  const revokeMutation = useMutation({
    mutationFn: async (provider: string) => {
      const response = await fetch('/api/oauth/revoke', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ provider }),
      });

      if (!response.ok) {
        throw new Error(`Token revocation failed for ${provider}`);
      }

      return response.json();
    },
    onSuccess: (data, provider) => {
      queryClient.invalidateQueries({ queryKey: ['/api/oauth/tokens'] });
      queryClient.invalidateQueries({ queryKey: ['/api/oauth/status'] });
      
      toast({
        title: "Connection Removed",
        description: `${provider} connection removed successfully`,
      });
    },
    onError: (error: any, provider) => {
      console.error(`Token revocation failed for ${provider}:`, error);
      
      toast({
        title: "Revocation Failed",
        description: `Failed to remove ${provider} connection`,
        variant: "destructive",
      });
    },
  });

  // Logout mutation
  const logoutMutation = useMutation({
    mutationFn: async (provider?: string) => {
      return await oauthManager.logout(provider);
    },
    onSuccess: (success, provider) => {
      queryClient.invalidateQueries({ queryKey: ['/api/oauth/tokens'] });
      queryClient.invalidateQueries({ queryKey: ['/api/oauth/status'] });
      
      if (success) {
        toast({
          title: "Logged Out",
          description: provider ? `Logged out from ${provider}` : "Logged out from all platforms",
        });
      } else {
        toast({
          title: "Logout Issues",
          description: "Some connections may require manual logout. Page will refresh shortly.",
          variant: "destructive",
        });
      }
    },
    onError: (error: any, provider) => {
      console.error('Logout failed:', error);
      
      toast({
        title: "Logout Failed",
        description: "Logout encountered issues. Please try again or refresh the page.",
        variant: "destructive",
      });
    },
  });

  const refreshToken = async (provider: string): Promise<boolean> => {
    try {
      await refreshMutation.mutateAsync(provider);
      return true;
    } catch (error) {
      return false;
    }
  };

  const revokeToken = async (provider: string): Promise<boolean> => {
    try {
      const result = await revokeMutation.mutateAsync(provider);
      return result.success;
    } catch (error) {
      return false;
    }
  };

  const logout = async (provider?: string): Promise<boolean> => {
    try {
      return await logoutMutation.mutateAsync(provider);
    } catch (error) {
      return false;
    }
  };

  const hasValidToken = (provider: string): boolean => {
    const tokenStatus = status[provider];
    return tokenStatus?.connected && !tokenStatus?.needsRefresh;
  };

  const getToken = async (provider: string): Promise<string | null> => {
    try {
      return await getValidToken(provider);
    } catch (error) {
      console.error(`Failed to get token for ${provider}:`, error);
      
      // Try to handle the failure
      const handled = await handleTokenFailure(provider, error);
      if (handled) {
        // Retry once after handling
        return await getValidToken(provider);
      }
      
      return null;
    }
  };

  return {
    tokens: tokens as Record<string, any>,
    status: status as Record<string, any>,
    isLoading: tokensLoading || statusLoading || !isInitialized,
    refreshToken,
    revokeToken,
    logout,
    hasValidToken,
    getToken,
  };
}

// Helper hook for specific provider
export function useProviderOAuth(provider: string) {
  const oauth = useOAuth();
  
  return {
    token: oauth.tokens[provider],
    status: oauth.status[provider],
    isConnected: oauth.hasValidToken(provider),
    refresh: () => oauth.refreshToken(provider),
    revoke: () => oauth.revokeToken(provider),
    getToken: () => oauth.getToken(provider),
  };
}