import { useState, useEffect } from 'react';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Badge } from '@/components/ui/badge';
import { Alert, AlertDescription } from '@/components/ui/alert';
import { RefreshCw, AlertCircle, CheckCircle, ExternalLink } from 'lucide-react';
import { apiRequest } from '@/lib/queryClient';

interface TokenValidation {
  platform: string;
  isValid: boolean;
  error?: string;
  scopes?: string[];
  expiresAt?: string;
  needsRefresh: boolean;
  requiredScopes?: string[];
}

interface PlatformConnection {
  id: number;
  platform: string;
  platformUsername: string;
  isActive: boolean;
  connectedAt: string;
  oauthStatus?: TokenValidation;
}

export function OAuthStatusDashboard() {
  const queryClient = useQueryClient();
  
  const { data: connections = [], isLoading, error } = useQuery({
    queryKey: ['/api/platform-connections'],
    enabled: true
  });

  const refreshMutation = useMutation({
    mutationFn: async (platform: string) => {
      return apiRequest(`/api/oauth/refresh/${platform}`, {
        method: 'POST'
      });
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['/api/platform-connections'] });
    }
  });

  const getPlatformIcon = (platform: string) => {
    const icons: Record<string, string> = {
      facebook: '📘',
      instagram: '📷',
      linkedin: '💼',
      x: '🐦',
      youtube: '📺'
    };
    return icons[platform] || '🔗';
  };

  const getStatusColor = (status?: TokenValidation) => {
    if (!status) return 'secondary';
    return status.isValid ? 'default' : 'destructive';
  };

  const getStatusText = (status?: TokenValidation) => {
    if (!status) return 'Unknown';
    return status.isValid ? 'Valid' : 'Expired';
  };

  const handleReconnect = (platform: string) => {
    // Redirect to OAuth flow for the platform
    const oauthUrls: Record<string, string> = {
      facebook: `/auth/facebook`,
      instagram: `/auth/facebook`, // Instagram uses Facebook OAuth
      linkedin: `/auth/linkedin`,
      x: `/auth/twitter`,
      youtube: `/auth/google`
    };
    
    if (oauthUrls[platform]) {
      window.location.href = oauthUrls[platform];
    }
  };

  if (isLoading) {
    return (
      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <RefreshCw className="h-5 w-5 animate-spin" />
            Loading OAuth Status...
          </CardTitle>
        </CardHeader>
      </Card>
    );
  }

  if (error) {
    return (
      <Alert variant="destructive">
        <AlertCircle className="h-4 w-4" />
        <AlertDescription>
          Failed to load OAuth status. Please try again.
        </AlertDescription>
      </Alert>
    );
  }

  const expiredConnections = connections.filter((conn: PlatformConnection) => 
    conn.oauthStatus && !conn.oauthStatus.isValid
  );

  return (
    <div className="space-y-6">
      {expiredConnections.length > 0 && (
        <Alert variant="destructive">
          <AlertCircle className="h-4 w-4" />
          <AlertDescription>
            {expiredConnections.length} platform(s) need re-authentication to continue publishing posts.
          </AlertDescription>
        </Alert>
      )}

      <div className="grid gap-4 md:grid-cols-2 lg:grid-cols-3">
        {connections.map((connection: PlatformConnection) => (
          <Card key={connection.id} className="relative">
            <CardHeader className="pb-3">
              <CardTitle className="flex items-center justify-between text-base">
                <div className="flex items-center gap-2">
                  <span>{getPlatformIcon(connection.platform)}</span>
                  <span className="capitalize">{connection.platform}</span>
                </div>
                <Badge variant={getStatusColor(connection.oauthStatus)}>
                  {getStatusText(connection.oauthStatus)}
                </Badge>
              </CardTitle>
              <CardDescription>
                @{connection.platformUsername}
              </CardDescription>
            </CardHeader>
            
            <CardContent className="space-y-4">
              {connection.oauthStatus && (
                <div className="space-y-2 text-sm">
                  {connection.oauthStatus.error && (
                    <div className="text-red-600 bg-red-50 p-2 rounded">
                      {connection.oauthStatus.error}
                    </div>
                  )}
                  
                  {connection.oauthStatus.expiresAt && (
                    <div className="text-gray-600">
                      Expires: {new Date(connection.oauthStatus.expiresAt).toLocaleDateString()}
                    </div>
                  )}
                  
                  {connection.oauthStatus.scopes && (
                    <div className="text-gray-600">
                      Scopes: {connection.oauthStatus.scopes.slice(0, 2).join(', ')}
                      {connection.oauthStatus.scopes.length > 2 && ` +${connection.oauthStatus.scopes.length - 2} more`}
                    </div>
                  )}
                </div>
              )}
              
              <div className="flex gap-2">
                {connection.oauthStatus?.needsRefresh && (
                  <Button
                    size="sm"
                    variant="outline"
                    onClick={() => refreshMutation.mutate(connection.platform)}
                    disabled={refreshMutation.isPending}
                    className="flex-1"
                  >
                    {refreshMutation.isPending ? (
                      <RefreshCw className="h-3 w-3 animate-spin mr-1" />
                    ) : (
                      <RefreshCw className="h-3 w-3 mr-1" />
                    )}
                    Refresh
                  </Button>
                )}
                
                {connection.oauthStatus && !connection.oauthStatus.isValid && (
                  <Button
                    size="sm"
                    onClick={() => handleReconnect(connection.platform)}
                    className="flex-1"
                  >
                    <ExternalLink className="h-3 w-3 mr-1" />
                    Reconnect
                  </Button>
                )}
                
                {connection.oauthStatus?.isValid && (
                  <div className="flex items-center text-green-600 text-sm">
                    <CheckCircle className="h-4 w-4 mr-1" />
                    Ready to publish
                  </div>
                )}
              </div>
            </CardContent>
          </Card>
        ))}
      </div>
      
      {connections.length === 0 && (
        <Card>
          <CardHeader>
            <CardTitle>No Platform Connections</CardTitle>
            <CardDescription>
              Connect your social media accounts to start publishing content.
            </CardDescription>
          </CardHeader>
          <CardContent>
            <Button onClick={() => window.location.href = '/platform-connections'}>
              <ExternalLink className="h-4 w-4 mr-2" />
              Connect Platforms
            </Button>
          </CardContent>
        </Card>
      )}
    </div>
  );
}