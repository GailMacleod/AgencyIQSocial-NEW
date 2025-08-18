import { useEffect, useState } from 'react';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { apiRequest } from '@/lib/queryClient';
import { useToast } from '@/hooks/use-toast';

interface TokenStatus {
  platform: string;
  isValid: boolean;
  error?: string;
  needsRefresh: boolean;
  expiresAt?: string;
}

interface TokenValidationResult {
  validTokens: TokenStatus[];
  expiredTokens: TokenStatus[];
  needsAttention: boolean;
}

export function useTokenValidation() {
  const [isValidating, setIsValidating] = useState(false);
  const { toast } = useToast();
  const queryClient = useQueryClient();

  // Query to get current token status
  const { data: tokenStatus, isLoading } = useQuery<TokenStatus[]>({
    queryKey: ['/api/platform-connections'],
    select: (data: any[]) => {
      // Filter out connections without oauthStatus and map to TokenStatus
      return data
        .filter(conn => conn.oauthStatus) // Only include connections with oauthStatus
        .map(conn => ({
          platform: conn.oauthStatus.platform,
          isValid: conn.oauthStatus.isValid,
          error: conn.oauthStatus.error,
          needsRefresh: conn.oauthStatus.needsRefresh,
          expiresAt: conn.oauthStatus.expiresAt
        }));
    },
    refetchInterval: 5 * 60 * 1000, // Check every 5 minutes
    staleTime: 2 * 60 * 1000, // Consider stale after 2 minutes
  });

  // Mutation to refresh tokens
  const refreshTokenMutation = useMutation({
    mutationFn: async (platform: string) => {
      return apiRequest(`/api/oauth/refresh/${platform}`, {
        method: 'POST',
      });
    },
    onSuccess: (data, platform) => {
      if (data.success) {
        toast({
          title: `${platform} reconnected`,
          description: `Successfully refreshed ${platform} authentication.`,
        });
        // Invalidate connections to refresh UI
        queryClient.invalidateQueries({ queryKey: ['/api/platform-connections'] });
      }
    },
    onError: (error, platform) => {
      toast({
        title: `${platform} refresh failed`,
        description: `Please manually reconnect ${platform} in Connect Platforms.`,
        variant: 'destructive',
      });
    },
  });

  // Auto-refresh tokens on app load and periodically
  useEffect(() => {
    if (!tokenStatus) return;

    const expiredTokens = tokenStatus.filter(token => !token.isValid && token.needsRefresh);
    const soonToExpire = tokenStatus.filter(token => {
      if (!token.expiresAt) return false;
      const expiryTime = new Date(token.expiresAt).getTime();
      const now = Date.now();
      const hoursUntilExpiry = (expiryTime - now) / (1000 * 60 * 60);
      return hoursUntilExpiry < 24 && hoursUntilExpiry > 0; // Expires within 24 hours
    });

    // Auto-refresh tokens that have refresh tokens
    expiredTokens.forEach(token => {
      if (token.platform === 'facebook' || token.platform === 'instagram' || token.platform === 'linkedin') {
        refreshTokenMutation.mutate(token.platform);
      }
    });

    // Show warnings for tokens expiring soon
    soonToExpire.forEach(token => {
      const expiryTime = new Date(token.expiresAt!).getTime();
      const hoursUntilExpiry = Math.round((expiryTime - Date.now()) / (1000 * 60 * 60));
      
      toast({
        title: `${token.platform} token expiring soon`,
        description: `Your ${token.platform} connection expires in ${hoursUntilExpiry} hours. Consider reconnecting.`,
        variant: 'default',
      });
    });
  }, [tokenStatus, refreshTokenMutation, toast]);

  // Manual validation function
  const validateAllTokens = async () => {
    setIsValidating(true);
    try {
      await queryClient.invalidateQueries({ queryKey: ['/api/platform-connections'] });
      await queryClient.refetchQueries({ queryKey: ['/api/platform-connections'] });
    } finally {
      setIsValidating(false);
    }
  };

  // Get validation results
  const getValidationResults = (): TokenValidationResult => {
    if (!tokenStatus || tokenStatus.length === 0) {
      return { validTokens: [], expiredTokens: [], needsAttention: false };
    }

    const validTokens = tokenStatus.filter(token => token.isValid);
    const expiredTokens = tokenStatus.filter(token => !token.isValid);
    const needsAttention = expiredTokens.length > 0;

    return { validTokens, expiredTokens, needsAttention };
  };

  return {
    tokenStatus,
    isLoading,
    isValidating,
    validateAllTokens,
    refreshToken: refreshTokenMutation.mutate,
    isRefreshing: refreshTokenMutation.isPending,
    getValidationResults,
  };
}